# abi-interleave

Three processes, three ABIs, one kernel, at the same time.

A shell loop prints `L` as an ordinary ELF process, `interleave.exe` prints `W`
through NT calls, and `interleave.macho` prints `M` through Darwin calls. They
are started together, so the output shows the scheduler moving between them:
`LLLWWWMMMLLL...` rather than one letter's whole run followed by the next.

That is what the per-task dispatch has to get right. Each process carries the
ABI its image was loaded with, and every trap goes to the package that answers
to it - the numbers collide between the three, so servicing a trap by number
alone would answer some of them from the wrong package. The case fails if any
letter is missing or if the letters never change hands.

    cargo xtask starry app qemu -t abi-interleave --arch x86_64
