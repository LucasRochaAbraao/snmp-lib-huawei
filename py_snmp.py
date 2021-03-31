#!/usr/bin/env python3
# coding=utf-8

##############################
#     LUCAS ROCHA ABRAÃO     #
#   lucasrabraao@gmail.com   #
#  github: LucasRochaAbraao  #
#      ver: 1.0  26/06/2020  #
##############################

import sys
from textwrap import wrap
from pysnmp import hlapi

def walk(host, comnty, oid):
    # http://snmplabs.com/pysnmp/docs/pysnmp-hlapi-tutorial.html
    # http://snmplabs.com/pysnmp/examples/hlapi/asyncore/manager/cmdgen/advanced-topics.html
    # http://snmplabs.com/pysnmp/examples/hlapi/asyncore/manager/cmdgen/advanced-topics.html
    var_list = []
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in hlapi.nextCmd(hlapi.SnmpEngine(),
                              hlapi.CommunityData(comnty),
                              hlapi.UdpTransportTarget((host, 161)),
                              hlapi.ContextData(),
                              hlapi.ObjectType(hlapi.ObjectIdentity(oid)),
                              lexicographicMode=False):
        if errorIndication:
            print(errorIndication, file=sys.stderr)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                                file=sys.stderr)
            break
        else:
            for varBind in varBinds:
                str_varBind = str(varBind)
                #print(varBind)
                var_list.append(str_varBind[str_varBind.index('=')+2:])
    return var_list

async def status(olt, comnty, pon=None):
    """ Retorna o status das ONUs da pon passada,
    1 = online,  2 = offline"""

    try: # Tentando realizar o snmpwalk
        if pon: # pon específica
            status_snmp = walk(olt, comnty, f'1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15.{pon}') # oid que retorna ONT status (online = 1, offline = 2)
        else: # olt inteira
            status_snmp = walk(olt, comnty, '1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15')
    except: # timeout
        print("Não foi possível realizar o snmp walk dos status. Aguarde alguns instantes e tente novamente. Saindo...")
        sys.exit()
    status = []
    for stat in status_snmp:
        if stat == '1':
            status.append('online')
        elif stat == '2':
            status.append('offline')
    return status

async def descricao(olt, comnty, pon=None):
    """ Retorna as descrições das ONUs da PON passada."""

    try: # Tentando realizar o snmpwalk
        if pon: # pon específica
            descs_snmp = walk(olt, comnty, f'1.3.6.1.4.1.2011.6.128.1.1.2.43.1.9.{pon}') # oid que retorna descrições
        else: # olt inteira
            descs_snmp = walk(olt, comnty, '1.3.6.1.4.1.2011.6.128.1.1.2.43.1.9') # oid que retorna descrições
    except: # timeout
        print("Não foi possível realizar o snmp walk das descrições. Aguarde alguns instantes e tente novamente. Saindo...")
        sys.exit()
    return descs_snmp

async def last_downtime(olt, comnty, pon=None):
    """ Retorna data + hora da última queda de cada onu da pon passada. """

    try: # Tentando realizar o snmpwalk
        if pon: # pon específica
            last_downtime = walk(olt, comnty, f'1.3.6.1.4.1.2011.6.128.1.1.2.46.1.23.{pon}') # oid que retorna o Downtime (em hexadecimal)
        else: # olt inteira
            last_downtime = walk(olt, comnty, '1.3.6.1.4.1.2011.6.128.1.1.2.46.1.23') # oid que retorna o Downtime (em hexadecimal)
    except: # timeout
        print("Não foi possível realizar o snmp walk do último downtime. Aguarde alguns instantes e tente novamente. Saindo...")
        sys.exit()

    last_downtime_formatado = []
    for dados in last_downtime:
        onu_dt_lst = wrap(dados[2:], 2) # retira o 0x, retorno vem como: 0x07e40607150a22002d0300. E wrap() separa em pares.
        ano, mes, dia, hora, minuto, segundo = onu_dt_lst[0] + onu_dt_lst[1], onu_dt_lst[2], onu_dt_lst[3], onu_dt_lst[4], onu_dt_lst[5], onu_dt_lst[6]
        last_downtime_formatado.append(f'{int(dia, 16):02d}-{int(mes, 16):02d}-{int(ano, 16)} {int(hora, 16):02d}:{int(minuto, 16):02d}:{int(segundo, 16):02d}')
    return last_downtime_formatado

async def last_down_cause(olt, comnty, pon=None):
    """ Retorna o motivo da última queda de cada onu da pon passada. """

    try: # Tentando realizar o snmpwalk
        if pon: # pon específica
            resultado = walk(olt, comnty, f'1.3.6.1.4.1.2011.6.128.1.1.2.46.1.24.{pon}') # oid que retorna descrições
        else: # olt inteira
            resultado = walk(olt, comnty, '1.3.6.1.4.1.2011.6.128.1.1.2.46.1.24') # oid que retorna descrições
    except: # timeout
        print("Não foi possível realizar o snmp walk do last down cause. Aguarde alguns instantes e tente novamente. Saindo...")
        sys.exit()
    resultados_value = []
    for res in resultado:
        if res == '2':
            resultados_value.append("___LOS___")
        elif res == '13':
            resultados_value.append("dying-gasp")
        elif res == '-1':
            resultados_value.append("info_zerada")
        else:
            resultados_value.append("cond_estranha")
    return resultados_value                 # retorna uma lista com as descrições

async def potencia(olt, comnty, pon=None, tipo='onu'):
    """ Retorna o sinal rx de cada onu na pon passada.""" # Saída é meiia estranha :/ ex: ['HWTC\x84½\x00\x9a', 'HWTC¶\x9eD\x9c']

    try: # Tentando realizar o snmpwalk
        if pon: # pon específica
            if tipo == 'onu':
                sinais_snmp = walk(olt, comnty, f'1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4.{pon}') # oid que retorna Potência RX das ONUs
            elif tipo == 'olt':
                sinais_snmp = walk(olt, comnty, f'.1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6.{pon}') # oid que retorna Potência TX das ONUs
            else:
                print(f'Para consutar a potência, escolha apenas "onu" ou "olt". Você escolheu: {tipo}')
        else: # olt inteira
            if tipo == 'onu':
                sinais_snmp = walk(olt, comnty, '1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4') # oid que retorna Potência RX das ONUs
            elif tipo == 'olt':
                sinais_snmp = walk(olt, comnty, '.1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6') # oid que retorna Potência TX das ONUs
            else:
                print(f'Para consutar a potência, escolha apenas "onu" ou "olt". Você escolheu: {tipo}')
    except: # timeout
        print("Não foi possível realizar o snmp walk das potências. Aguarde alguns instantes e tente novamente. Saindo...")
        sys.exit()
    sinais = []
    for sinal in sinais_snmp:
        temp = f'{int(sinal) / 100:.2f}'
        if temp == '21474836.47':
            temp = 'offline'
        sinais.append(str(temp))
    return sinais

async def serial(olt, comnty, pon=None):
    """ Retorna o serial de cada onu na pon passada. """ # falta validar

    try: # Tentando realizar o snmpwalk
        if pon: # pon específica
            seriais_snmp = walk(olt, comnty, f'1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3.{pon}') # oid que retorna descrições
        else: # olt inteira
            seriais_snmp = walk(olt, comnty, '1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3') # oid que retorna descrições
    except: # timeout
        print("Não foi possível realizar o snmp walk dos seriais. Aguarde alguns instantes e tente novamente. Saindo...")
        sys.exit()
    seriais = []
    for serial in seriais_snmp:
        seriais.append(serial[2:].upper()) # extrai o valor da descrição
    return seriais             # retorna uma lista com as descrições

async def temp_placas(olt, comnty, pon):
    """ Retorna a temperatura de cada placa da olt. """
    temp_placas = walk(olt, comnty, '1.3.6.1.4.1.2011.2.6.7.1.1.2.1.10')
    temp_values = []
    for temp in temp_placas:
        if temp == '2147483647':
            temp = 'Sem Info'
        temp_values.append(temp) # extrai o valor da descrição
    return temp_values                 # retorna uma lista com as descrições

async def uptime_olt(olt, comnty):
    """
    Uptime da OLT em ticks. Conversões:
    segundos = ticks / 100
    minutos = ticks / 6,000
    horas = ticks / 360,000
    dias = ticks / 8,640,000
    Por padrão, retorno em dias.
    """
    uptime_ticks = walk(olt, comnty, '1.3.6.1.2.1.1.3') # Uptime da OLT em ticks

    tempo = float(float(uptime_ticks[0]) / 60 / 60 /24 / 100)
    dias = int(tempo)
    horas = (tempo % int(tempo)) * 24
    minutos = (horas % int(horas) ) * 60
    return [dias, int(horas), int(minutos)]
     # Dias
    # printa aproximadamente os dias, não é exato.
    #return f'Uptime da olt \'{olt}\' é de aproximadamente {uptime / 100:.0f} dias.'
