# FlowWalker
FlowWalker is a practical off-line taint analysis framework with high efficiency and low overhead.

Dynamic Taint Analysis (DTA) is a data-flow analyzing technique, which monitors the taint sources and tracks the propagations of external inputs. With the result of DTA, it is possible to tell what routines and which conditional jumps along the process are influenced by external data thus manually controllable.

FlowWalker aims to give a pratical, available and extensible DTA framework. Existing DTA tools analyze data propagation along with the target process execution, resulting in unacceptably heavy burden attached to the process. FlowWalker separates the analysis procedure from the execution, thus it consists of a dynamic instrumenting module Recorder, which gives out a complete trace of the process, and a trace analyzer Replayer, which analyzes the trace and makes data flow tracking.

In addition, FlowWalker also contains a standalone module, Recognizer. Recognizer is used for automatically analyze the structure and format of unknown program input data. The analysis is based on the taint analysis result, which implies the relations among the input bytes.

For more theoretical introduction, please follow this project. The technical thesis will be pasted here after publications. The source codes of Recorder is ultimately open here. The sources of Replayer is of large amount and will be put here after careful collation. The binary execution files of Replayer and Recognizer are placed here for trial and tests. The operation guidelines of the whole system is pasted below, while translation is to be added.


1、Recorder
这是进行动态测试并记录进程快照的模块，文件Recorder.dll。该模块应在Intel Pin 2.12.55942版本上使用，其他版本的Pin无法加载。
使用方式：命令行下执行以下命令（假设当前目录为放置Recorder.dll文件的目录）
[PIN_HOME_PATH]\ia32\bin\pin.exe -t [TOOL_PATH]\Recorder.dll -tf [参数1] -op [参数2] -logsz [参数3] -- [参数4] [参数5]
其中，
参数1为执行文件格式测试时，用于测试程序打开的文件名，不含路径；
参数2为指定的输出日志文件的路径，应传入完整的绝对路径；
参数3为输出日志文件中进程快照日志的初始体积，以MB为单位，应为512的整数倍数，在快照写满该数据大小之后，将继续增长该大小的文件体积。默认为1024；
参数4为被测程序的启动命令，即可用于“运行...”命令启动程序的命令；
参数5为程序打开的文件名，应包含路径。该参数可选，若指定时，被测程序启动后直接打开该文件，否则可以在被测程序启动后手动打开文件。
另外，对于某些多进程被测程序，如IE，也可以改用如下命令：
[PIN_HOME_PATH]\ia32\bin\pin.exe -pid [参数4] -t [TOOL_PATH]\Recorder.dll -tf [参数1] -op [参数2] -logsz [参数3]
其中，参数1、2、3意义不变，参数4为需要pin注入到的已经启动的进程的pid。
此外，还可以额外指定符号文件，用于在生成的日志中准确记录函数名信息，方法为在\t Recorder之后使用-symbol_path [符号文件路径]命令。
在执行后，会在指定的位置生成三个日志文件：image_list.fw、bbl_list.fw、process.fw。其中第一个记录了所有二进制映像信息，包括序号、加载的低地址与高地址、映像名；第二个记录了所有基本块信息，包括汇编指令序列、内存读写标记等；第三个为程序执行快照。

2、Replayer
这是进行静态污点分析的模块，文件Replayer.exe。该程序使用方法为执行以下命令：
Replayer [参数1] [参数2] [参数3] [参数4]
其中前三个参数依次为上述Recorder模块生成的三个日志文件完整路径与文件名，参数4为被测文件的大小，单位为Byte。
另一种执行方式为直接执行Replayer.exe，之后按照提示输入上述四个参数。
执行之后，将在上述三个日志的同一目录下生成另外两个日志：TaintTrace.txt与misc.txt。前者是污点跟踪的结果记录，行数等于被测文件的字节数，每一行记录了对应字节在程序处理过程中的处理和传递流程。后者共两行，分别记录了涉及污点数据处理的指令中有CMP指令将污点数据与静态常量进行比较且击中的所有时间戳，以及有LEA指令将污点内存数据进行取址操作的时间戳。

3、Recognizer
这是进行文件格式分片的模块，文件Recognizer.exe。该程序使用方法为执行以下命令：
Replayer [参数1] [参数2] [参数3] [参数4] [参数5]
其中参数1为image_list.fw路径，参数2为bbl_list.fw路径，参数3为TaintTrace.txt路径，参数4为misc.txt路径，参数5为被测文件大小，单位为Byte。
执行之后，将文件分片结果输出到与TaintTrace.txt同一目录下的fragmentation.txt文件中，形式为顺序的每个分片一行，指明低字节:长度，字节从0开始计数；如果该片段被判定为静态字段，则后接一个S标识。如“23:4 S”意即第24到第27字节共4个字节被划分为一个结构单元，且判定为静态字段。
