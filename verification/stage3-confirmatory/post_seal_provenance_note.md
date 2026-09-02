# Stage 3 post-seal provenance note

The outcome-blind constructor finalized the R4 package before repository commit
`3fec886a9fdd1fbcde66f7732f972ec51c33823e`. The official construction verifier
then passed twice, the 11-entry detached seal passed twice, and a separate
outcome-blind mechanical audit reported no remaining blocker. The annotated tag
`stage3-construction-seal-2026-09-01` binds those exact bytes to that commit.

After all R4 file edits and validation were complete, the constructor called a
team-status tool to check audit availability. That status response unexpectedly
included another completed agent's discussion of historical Stage 1/2 results.
The constructor reported the exposure immediately, did not open or search any
historical result path, made no subsequent file change, and stopped work. The
coordinator independently rechecked the unchanged R4 hashes afterward.

Accordingly, the selection record's blindness attestation applies to workflow
construction, final inclusion, every repair, and the completed R4 content seal.
It must not be read as claiming that the constructor remained informationally
unexposed after the seal was already immutable. This note is additive and is not
one of the 11 sealed entries.

Final R4 commitments:

- ordered workflow manifest: `172cb6ce368f3ba819407f02e5b31ae33e0755ea49f0decc291756e2c632b3b3`;
- detached seal file: `10a707d982a0bc5f647d671b4a135dbff9b792640b117376e47abb90cbb7d297`;
- selection record: `06b412b406bda88b687c0a676f09fc60424efa71b1f5d4d5531e7bb0b08643ed`;
- construction verifier: `6e18a915a57cfaf5e1b615f2889c05e9091e742ba46241a5da5b2d5460a1fba8`;
  and
- Stage 4 observability projector: `fae7b872538288c85cd383f19c3383680e997c792295f820a3d59cccaa785293`.
