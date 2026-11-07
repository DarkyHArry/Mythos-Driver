# Mythos Driver

Projeto de driver de kernel para Windows (AntiCheatDriver) com ferramentas de assinatura e teste.

## O que é

- `AntiCheatDriver`: driver de kernel WDM/KMDF em C (x64) que monitora integridade de processos protegidos (anti-cheat).
- `BasicTest`: cliente de teste .NET que valida ambiente e interface IOCTL do driver.
- `DriverSigner`: ferramenta de assinatura de arquivos PE (.sys/.exe/.dll) via signtool.
- `SignedDrivers`: driver assinado para distribuicao/teste.
- Scripts PowerShell para verificacao/exportacao de certificados.

## Como funciona

### Driver (AntiCheatDriver)

1. `DriverEntry` (src/DriverEntry.c) cria o dispositivo e registra callbacks de processo, thread e image load.
2. Callbacks do kernel notificam criacao/remocao de processos e carregamento de modulos.
3. Processos protegidos sao rastreados (lista com modulos e hashes) em ProcessCallbacks.c.
4. Timer DPC executa varredura periodica (MemoryScan.c) verificando integridade de modulos, hooks de API e injecao de codigo.
5. Violacoes sao armazenadas em buffer circular e expostas via IOCTL.
6. DeviceControl.c trata IOCTLs: registrar/desregistrar processos, scan de memoria, consulta de violacoes, configuracao.

### Deteccao de jogos

- `AcIsGameProcess` (DriverUtils.c) identifica processos de jogo por nome.
- `AcIsSuspiciousModule` (ImageLoadCallbacks.c) compara modulos carregados com lista de nomes suspeitos (basename, case-insensitive).
- `AcDetectApiHooks`, `AcDetectCodeInjection`, `AcDetectThreadHijack` em MemoryScan.c.
- `AC_CONFIG` permite ativar/desativar cada monitoramento e bloquear modulos suspeitos.

### Assinatura (DriverSigner)

- Valida PE (MZ/PE, x64), carrega PFX, invoca signtool com SHA256/SHA1 + timestamp.
- Gera arquivo assinado e verifica com `signtool verify`.

## Estrutura

```
AntiCheatDriver/   codigo do driver (src/, include/, CMakeLists.txt)
BasicTest/         cliente de teste
DriverSigner/      assinador de driver
SignedDrivers/     .sys assinado
*.ps1              verificacao de certificados
```

## Compilacao do driver

Requisitos: Windows, Visual Studio (workload C++), WDK 10.0.26100.0, CMake 3.20+.

```powershell
cd AntiCheatDriver
cmake -S . -B build -A x64
cmake --build build --config Release
```

Saida: `build/Release/AntiCheatDriver.sys`.

Para assinar automaticamente no build:

```powershell
cmake -S . -B build -A x64 -DSIGN_DRIVER=ON
cmake --build build --config Release
```

## Assinatura de driver

```powershell
dotnet run --project DriverSigner -- --file AntiCheatDriver.sys --cert TestDriverCert.pfx --password <senha> --verify
```

### Como a assinatura funciona

1. Validacao do arquivo: `DriverSigner` verifica se o arquivo e um PE valido (cabecalho MZ/PE) e arquitetura x64.
2. Carregamento do certificado: le o PFX com chave privada e valida periodo de validade.
3. Assinatura: invoca `signtool.exe` com SHA256 (ou SHA1), carimbo de tempo (timestamp) e descricao.
4. Saida: gera o arquivo assinado (`.signed.sys` por padrao ou caminho informado em `--output`).
5. Verificacao: com `--verify`, executa `signtool verify /v /pa` para confirmar a assinatura.

Opcoes principais:
- `--testsign`: modo de test signing (para desenvolvimento, requer test signing habilitado no boot).
- `--timestamp`: servidor de timestamp (padrao: http://timestamp.digicert.com).
- `--sha256`: usa SHA256 (padrao true).
- `--verbose`: saida detalhada.

O `signtool` e localizado automaticamente nos caminhos do Windows SDK/Visual Studio.

## Teste

1. Habilitar test signing: `bcdedit /set testsigning on` e reiniciar.
2. Carregar o driver: `sc create AntiCheatDriver type= kernel binPath= <caminho>\AntiCheatDriver.sys` e `sc start AntiCheatDriver`.
3. Executar `BasicTest` para validar IOCTLs.

## Uso em jogos (anti-cheat)

O driver identifica processos de jogo (lista em `AcIsGameProcess`, em `DriverUtils.c`) e monitora apenas esses processos para reduzir overhead. Para cada processo rastreado:

- Carregamento de modulos e comparacao com lista de modulos suspeitos (`AcIsSuspiciousModule` em `ImageLoadCallbacks.c`).
- Varredura de memoria (`AcScanProcessMemory`/`AcScanMemoryRegion` em `MemoryScan.c`) para detectar alteracoes.
- Deteccao de hooks de API (`AcDetectApiHooks`) e injecao de codigo (`AcDetectCodeInjection`).
- Deteccao de thread hijack (`AcDetectThreadHijack`).
- Violacoes registradas com tipo, PID, endereco e descricao, expostas via `IOCTL_AC_GET_VIOLATIONS`.

A configuracao (`AC_CONFIG`) permite ativar/desativar cada monitoramento e bloquear modulos suspeitos (`BlockSuspiciousModules`).

## Interface IOCTL

- `IOCTL_AC_REGISTER_PROCESS` - registra processo para monitoramento
- `IOCTL_AC_UNREGISTER_PROCESS` - remove processo do monitoramento
- `IOCTL_AC_SCAN_MEMORY` - varre regiao de memoria
- `IOCTL_AC_QUERY_INTEGRITY` - consulta integridade de modulos
- `IOCTL_AC_GET_VIOLATIONS` - obtem violacoes registradas
- `IOCTL_AC_SET_CONFIG` - atualiza configuracao do driver

## Melhorias implementadas

- Build Debug/Release corrigido.
- Migracao ExAllocatePoolWithTag -> ExAllocatePool2.
- Regras de detecao revisadas.
- Testes IOCTL no BasicTest.
- Documentacao de IOCTLs no header.
- Opcao SIGN_DRIVER no CMake e CI.

