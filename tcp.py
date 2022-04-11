import asyncio
from datetime import datetime
from typing import List

import tcp
from grader.tcputils import *


# Usado para gerar bytes aleatórios


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

        timers: list = []

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

        print('ℹ️ Called server _rdt_rcv with segment of length {}'.format(
            len(segment)))

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr,
                                                           dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4 * (flags >> 12):]

        print('ℹ️ Called server _rdt_rcv with payload of length {}'.format(
            len(payload)))

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
    asyncio_delay_time: float = 0.2

    # Mantém um timer interno.
    timer = None

    # Buffer de dados.
    buffer: List[bytes] = []

    # Registro de todos os timestamps de envio.
    sent_timestamp_log: List[datetime] = []

    def __init__(self, servidor, id_conexao, sequence_number: int):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        self.buffer = []
        self.sent_timestamp_log = []

        # Usado para identificar a conexão.
        self.sequence_number = sequence_number
        self.acknowledge_number = sequence_number + 1

        # self.timer = asyncio.get_event_loop().call_later(
        #     1, self._exemplo_timer
        # )
        # self.timer.cancel()   # é possível cancelar o timer chamando esse
        # método; esta linha é só um exemplo e pode ser removida

    def _timer_callback(self):
        print('[{}] timer callback called'.format(datetime.now()))

        if self.buffer:

            print(
                '[LOG] Making a [send] call from _timer_callback. Payload '
                'length: {}'.format(
                    len(self.buffer[-1])))

            print('Sending the following data (from buffer): {}'.format(
                self.buffer[-1]))

            # Get ACK and Seq_no from read_header of buffer[0]
            _, _, seq_no, ack_no, _, _, _, _ = read_header(self.buffer[-1])

            print('seq_no: {}'.format(seq_no))
            print('ack_no: {}'.format(ack_no))

            self.servidor.rede.enviar(
                self.buffer[-1], self.id_conexao.endereco_origem)

            self.sequence_number += len(self.buffer[-1]) - 20

            # self.sequence_number += len(self.buffer[0]) - 20
            self.buffer.clear()

            # payload = self.buffer.pop()
            # self.servidor.rede.enviar(payload,
            # self.id_conexao.endereco_destino)
        else:
            self.stop_timer()

        self.sent_timestamp_log.append(datetime.now())

    def start_timer(self):
        # self.stop_timer()
        self.timer = asyncio.get_event_loop().call_later(
            self.asyncio_delay_time, self._timer_callback)

    def stop_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        asyncio.get_event_loop().call_later(
            self.asyncio_delay_time, self._timer_callback
        )

        print(' ! Called _rdt_rcv from Conexao with payload length: {}'.format(
            len(payload)))

        # FIXME As flags devem ser tratadas aqui.

        # TODO: trate aqui o recebimento de segmentos provenientes da camada
        #  de rede.
        # Chame self.callback(self, dados) para passar dados para a camada
        # de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos
        # em ordem.

        if seq_no != self.acknowledge_number:
            return

        if self.buffer:
            if self.sequence_number + (len(self.buffer[0]) - 20) == ack_no:
                self.sequence_number += len(self.buffer[0]) - 20

                self.buffer.pop()

                if len(self.buffer) == 0:
                    self.stop_timer()

        if seq_no > self.sequence_number - 1 and (
                # if self.sequence_number <= seq_no and (
                flags & FLAGS_ACK) == FLAGS_ACK:
            # self.start_timer()

            self.sequence_number = seq_no

            if len(self.buffer) > 0:
                self.buffer.pop()
                if len(self.buffer) == 0:
                    self.stop_timer()
                else:
                    self.start_timer()

        if flags & FLAGS_FIN == FLAGS_FIN:
            self.acknowledge_number += 1

            # Envia a confirmação de recebimento com a flag ACK.
            dados = fix_checksum(
                make_header(
                    src_port=self.id_conexao.porta_destino,
                    dst_port=self.id_conexao.porta_origem,
                    seq_no=self.sequence_number,
                    ack_no=self.sequence_number + 1,
                    flags=FLAGS_ACK
                ),
                dst_addr=self.id_conexao.endereco_destino,
                src_addr=self.id_conexao.endereco_origem
            )

            self.servidor.rede.enviar(
                dados, self.id_conexao.endereco_origem)

            self.callback(self, b'')

        if flags & (FLAGS_SYN | FLAGS_ACK) == (FLAGS_SYN | FLAGS_ACK):
            dados = fix_checksum(
                make_header(
                    src_port=self.id_conexao.porta_destino,
                    dst_port=self.id_conexao.porta_origem,

                    # TODO Isso tá estranho
                    seq_no=seq_no,
                    ack_no=ack_no,
                    flags=FLAGS_ACK
                ),
                dst_addr=self.id_conexao.endereco_destino,
                src_addr=self.id_conexao.endereco_origem
            )

            self.servidor.rede.enviar(
                dados, self.id_conexao.endereco_origem)

            # self.callback(self, b'')

        self.callback(self, payload)

        if len(payload) != 0:
            self.acknowledge_number += len(payload)
            self.sequence_number = ack_no

            header = fix_checksum(
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

            should_send_payload: bool = not (flags & FLAGS_ACK) == FLAGS_ACK

            self.servidor.rede.enviar(
                header + payload if should_send_payload else header,
                self.id_conexao.endereco_origem)

            # self.sequence_number += len(dados)
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

            splited_data: list = []

            # Dados excedem o limite permitido.
            while len(dados) >= MSS:
                splited_data.append(dados[:MSS])
                dados = dados[MSS:]

            # Inicializa o timer antes do envio de todos os pacotes.
            self.start_timer()

            for payload in splited_data:
                header = fix_checksum(
                    make_header(
                        src_port=self.id_conexao.porta_destino,
                        dst_port=self.id_conexao.porta_origem,
                        seq_no=self.sequence_number,
                        ack_no=self.acknowledge_number,
                        flags=FLAGS_ACK  # | FLAGS_SYN
                    ),
                    dst_addr=self.id_conexao.endereco_origem,
                    src_addr=self.id_conexao.endereco_destino
                )

                print(
                    'Sending the following payload (from Conn.enviar): %r' %
                    payload)

                print('Ack: %r' % self.acknowledge_number)
                print('Seq: %r' % self.sequence_number)

                self.servidor.rede.enviar(
                    header + payload, self.id_conexao.endereco_origem)

                self.sequence_number += len(payload)

                print(' + Seq number updated to %r' % self.sequence_number)

                self.buffer.append(header + payload)

        else:
            is_syn_plus_ack: bool = read_header(dados)[4] & (
                    FLAGS_ACK | FLAGS_SYN) == (FLAGS_ACK | FLAGS_SYN)

            cabecalho = fix_checksum(
                make_header(
                    src_port=self.id_conexao.porta_destino,
                    dst_port=self.id_conexao.porta_origem,
                    seq_no=self.sequence_number,
                    ack_no=self.acknowledge_number,
                    flags=(
                            FLAGS_SYN | FLAGS_ACK) if is_syn_plus_ack
                    else FLAGS_ACK
                ),
                dst_addr=self.id_conexao.endereco_origem,
                src_addr=self.id_conexao.endereco_destino
            )

            response: bytes
            response = cabecalho + dados if not is_syn_plus_ack else cabecalho

            # NOTE: Enviar o cabeçalho quebra os testes 1 e 2.
            self.servidor.rede.enviar(
                response, self.id_conexao.endereco_origem)

            self.sequence_number = ++self.acknowledge_number
            print(' + Seq number updated to %r' % self.sequence_number)

            print(' ⚠️ Appending to buffer: %r' % response)
            self.buffer.append(response)

            # Inicia o timer (caso isso já não tenha sido feito).
            if not self.timer:
                self.start_timer()

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """

        # Remove a conexão da lista de conexões ativas.
        self.servidor.conexoes.pop(self.id_conexao.hash())

        header = fix_checksum(
            make_header(
                src_port=self.id_conexao.porta_origem,
                dst_port=self.id_conexao.porta_destino,
                seq_no=self.sequence_number,
                ack_no=self.acknowledge_number,
                flags=FLAGS_FIN
            ),
            src_addr=self.id_conexao.endereco_origem,
            dst_addr=self.id_conexao.endereco_destino
        )

        self.servidor.rede.enviar(header, self.id_conexao.endereco_destino)
