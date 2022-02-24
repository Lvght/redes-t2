import asyncio

import tcp
from grader.tcputils import *

# Usado para gerar bytes aleatórios
import os


class IdentificadorConexao:
    porta_destino: int
    porta_origem: int
    endereco_destino: str
    endereco_origem: str

    def hash(self):
        # Cria uma hash estática para o objeto
        return hash(self.porta_destino) \
               ^ hash(self.porta_origem) \
               ^ hash(self.endereco_destino) \
               ^ hash(self.endereco_origem)

    def __init__(self, id_conexao: tuple):
        self.porta_destino = id_conexao[3]
        self.porta_origem = id_conexao[1]
        self.endereco_destino = id_conexao[2]
        self.endereco_origem = id_conexao[0]


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser
        chamada sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
        flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr,
                                                           dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4 * (flags >> 12):]

        # Obtém os dados da conexão.
        id_conexao = IdentificadorConexao(
            (src_addr, src_port, dst_addr, dst_port))

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando
            # estabelecer uma conexão nova

            # TODO: talvez você precise passar mais coisas para o
            #  construtor de conexão

            conexao = self.conexoes[id_conexao.hash()] = \
                Conexao(self, id_conexao, sequence_number=seq_no)

            # Registra a conexão no callback caso este não seja nulo.
            if self.callback:
                self.callback(conexao)

            # TODO: você precisa fazer o handshake aceitando a conexão.
            #  Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.

            ack_no: int = seq_no + 1

            # Prepara a resposta do servidor.
            response = fix_checksum(
                make_header(
                    src_port=conexao.id_conexao.porta_destino,
                    dst_port=conexao.id_conexao.porta_origem,
                    seq_no=seq_no,
                    ack_no=ack_no,
                    flags=FLAGS_SYN | FLAGS_ACK
                ),
                dst_addr=conexao.id_conexao.endereco_origem,
                src_addr=conexao.id_conexao.endereco_destino
            )

            # self.rede.servidor.enviar(response, conexao.id_conexao.endereco_origem)

            conexao.enviar(response)

            if self.callback and not id_conexao.hash() in self.conexoes.keys():
                self.callback(conexao)

        elif id_conexao.hash() in self.conexoes.keys():
            # Passa para a conexão adequada se ela já estiver estabelecida

            conexao: tcp.Conexao = self.conexoes[id_conexao.hash()]

            conexao._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    sequence_number: int
    acknowledge_number: int
    id_conexao: IdentificadorConexao

    def __init__(self, servidor, id_conexao, sequence_number: int):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        # Usado para identificar a conexão.
        self.sequence_number = sequence_number
        self.acknowledge_number = sequence_number + 1

        self.timer = asyncio.get_event_loop().call_later(1,
                                                         self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida

        # self.timer.cancel()   # é possível cancelar o timer chamando esse
        # método; esta linha é só um exemplo e pode ser removida

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada
        #  de rede.
        # Chame self.callback(self, dados) para passar dados para a camada
        # de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos
        # em ordem.

        if seq_no != self.acknowledge_number:
            return

        if flags & FLAGS_FIN == FLAGS_FIN:
            self.acknowledge_number += 1

            # Envia a confirmação de recebimento com a flag ACK.

            dados = fix_checksum(
                make_header(
                    src_port=self.id_conexao.porta_destino,
                    dst_port=self.id_conexao.porta_origem,
                    seq_no=seq_no,
                    ack_no=ack_no,
                    flags=FLAGS_ACK
                ),
                dst_addr=self.id_conexao.endereco_destino,
                src_addr=self.id_conexao.endereco_origem
            )

            self.servidor.rede.enviar(dados,
                                      self.id_conexao.endereco_origem)

            self.callback(self, b'')

        self.callback(self, payload)
        if len(payload) != 0:
            self.acknowledge_number += len(payload)

            dados = fix_checksum(
                make_header(
                    src_port=self.id_conexao.porta_destino,
                    dst_port=self.id_conexao.porta_origem,
                    seq_no=self.sequence_number,
                    ack_no=self.acknowledge_number,
                    flags=flags | FLAGS_ACK
                ),
                dst_addr=self.id_conexao.endereco_origem,
                src_addr=self.id_conexao.endereco_destino
            )

            self.servidor.rede.enviar(dados,
                                      self.id_conexao.endereco_origem)

            self.sequence_number += len(dados)
            # print('recebido payload: %r' % payload)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser
        chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o
        # segmento
        # que você construir para a camada de rede.

        # Se o tamanho dos dados for maior que o tamanho maximo (MSS),
        # quebre-o em dois envios
        if len(dados) > MSS:
            self.enviar(dados[:MSS])
            self.enviar(dados[MSS:])

        else:

            # self.acknowledge_number = self.sequence_number + 1

            dados = fix_checksum(
                make_header(
                    src_port=self.id_conexao.porta_destino,
                    dst_port=self.id_conexao.porta_origem,
                    seq_no=self.sequence_number,
                    ack_no=self.acknowledge_number,
                    flags=FLAGS_ACK
                ),
                dst_addr=self.id_conexao.endereco_origem,
                src_addr=self.id_conexao.endereco_destino
            )

            self.servidor.rede.enviar(dados,
                                      self.id_conexao.endereco_origem)

            self.sequence_number = ++self.acknowledge_number

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        pass
