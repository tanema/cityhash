package cityhash

import (
	"testing"
)

var testcases = [][]uint64{
	{0x3df09dfc64c09a2b, 0x3cb540c392e51e29}, {0xc3cdc41e1df33513, 0x2c138ff2596d42f6}, {0x3149ba1dac77270d, 0x70e2e076e30703c},
	{0x2193fb7620cbf23b, 0x8b6a8ff06cda8302}, {0x4d09e42f09cc3495, 0x666236631b9f253b}, {0xdc07df53b949c6b, 0xd2b11b2081aeb002},
	{0xd183dcda5f73edfa, 0x3a93cbf40f30128c}, {0xb140a02ef5c97712, 0xb7d00ef065b51b33}, {0x26b6689960ccf81d, 0x55f23b27bb9efd94},
	{0x98ec31113e5e35d2, 0x5e4aeb853f1b9aa7}, {0x71fec0f972248915, 0x2170ec2061f24574}, {0xdf01a322c43a6200, 0x298b65a1714b5a7e},
	{0xd93251758985ee6c, 0x32a9e9f82ba2a932}, {0x77a4ccacd131d9ee, 0xe1d08eeb2f0e29aa}, {0xa154296d11362d06, 0xd0f0bf1f1cb02fc1},
	{0x3bab18b164396783, 0x47e385ff9d4c06f}, {0xac059617f5906673, 0x94d50d3dcd3069a7}, {0xa4375590b8ae7c82, 0x168fd42f9ecae4ff},
	{0x6b54fc38d6a84108, 0x32f4212a47a4665}, {0xf86af0b40dcce7b, 0x8d3c15d613394d3c}, {0x7ebc034235bc122f, 0xd9a7783d4edd8049},
	{0x9e4ea5a4941e097d, 0x547e048d5a9daaba}, {0xce2744521944f14c, 0x104f8032f99dc152}, {0x4ee107042e512374, 0x1e2c8c0d16097e13},
	{0x6ee1f817ce0b7aee, 0xe9dcb3507f0596ca}, {0xd367ff54952a958, 0xcdad930657371147}, {0x50d8a70e7a8d8f56, 0x256d150ae75dab76},
	{0xa90f761e8db1543a, 0xc339e23c09703cd8}, {0x23dacb811652ad4f, 0xc982da480e0d4c7d}, {0xc801faaa0a2e331f, 0x491dbc58279c7f88},
	{0x68dd76db9d64eca7, 0x36297682b64b67}, {0xb2e25964cd409117, 0xa010599d6287c412}, {0x9a8c431f500ef06e, 0xd848581a580b6c12},
	{0x7870765b470b2c5d, 0x78a9103ff960d82}, {0xea349dbc16c2e441, 0x38a7455b6a877547}, {0x5d9dde77353b1a6d, 0x11f58c54581fa8b1},
	{0xbf41e5376b9f0eec, 0x2252d21eb7e1c0e9}, {0xa1924cbf0b5f9222, 0x7f4872369c2b4258}, {0xf7dbc8433c89b274, 0x2f5f70581c9b7d32},
	{0x8ffe870ef4adc087, 0x65bea2be41f55b54}, {0x3df9b04434771542, 0xfeddce785ccb661f}, {0x7d2c38a926dc1b88, 0x5245b9eb4cd6791d},
	{0x864b1b28ec16ea86, 0x6a78a5a4039ec2b9}, {0x2e8c49d7c7aaa527, 0x5e2328fc8701db7c}, {0x3b69edadf357432b, 0x3a2e311c121e6bf2},
	{0xcd7a46850b95e901, 0xc57f7d060dda246f}, {0x8c1df927a930af59, 0xa462f4423c9e384e}, {0x9498fefb890287ce, 0xae68c2be5b1a69a6},
	{0x7a0b6dbab9a14e69, 0xc6d0a9d6b0e31ac4}, {0x843b58463c8df0ae, 0x74b258324e916045}, {0xcc76f429ea7a12bb, 0x5f30eaf2bb14870a},
	{0x328063229db22884, 0x67e9c95f8ba96028}, {0xf72c26e624407e66, 0xa0eb541bdbc6d409}, {0x405f66cf8cae1a32, 0xd7261740d8f18ce6},
	{0xd4eccebe9393ee8a, 0x2eb7867c2318cc59}, {0x7a61d8f552a53442, 0x821d1d8d8cfacf35}, {0x2247a4b2058d1c50, 0x1b3fa184b1d7bcc0},
	{0xe8b9ee96efa2d0e, 0x90122905c4ab5358}, {0x2e091b85660f1298, 0xbfe37fae1cdd64c9}, {0x7a9d77781ac53509, 0x4489c3ccfda3b39c},
	{0x9deefbcfa4cab1f1, 0xb58f5943cd2492ba}, {0xcfc6d7adda35797, 0x14c7d1f32332cf03}, {0xbce905900c1ec6ea, 0xc30f304f4045487d},
	{0x910b610de7a967bf, 0x801bc862120f6bf5}, {0xd1d44fe99451ef72, 0xec951ba8e51e3545}, {0xd3e86ac4f5eccfa4, 0xe5399df2b106ca1},
	{0x69afbc800606d0fb, 0x6104b97a9db12df7}, {0x909ae019d761d019, 0x368bf4aab1b86ef9}, {0xef79f28d874b9e2d, 0xb512089e8e63b76c},
	{0x8184bab36bb79df0, 0xc81929ce8655b940}, {0xbc61414f9802ecaf, 0x8edd1e7a50562924}, {0xd45e44c263e95c38, 0xdf61db53923ae3b1},
	{0x30e888af70df1e56, 0x4bee54bd47274f69}, {0x8b1d7bb4903c105f, 0xcfb1c322b73891d4}, {0x852c9499156a8f3, 0x3a180a6abfb79016},
	{0x939f31de14dcdc7b, 0xa68fdf4379df068}, {0x11b87fb1b900cc39, 0xe33e59b90dd815b1}, {0xa64760e4041447d0, 0xe3eac49f3e0c5109},
	{0x501f3e9b18861e44, 0x465201170074e7d8}, {0x154dd79fd2f984b4, 0xf11171775622c1c3}, {0xb7e164979d5ccfc1, 0x12cb4230d26bf286},
	{0x3ff6c8ac7c36b63a, 0x48bc8831d849e326}, {0x1a57313a32f22dde, 0x30af46e49850bf8b}, {0xe9029e6364286587, 0xae69f49ecb46726c},
	{0x3d8c90e27aa2e147, 0x2ec937ce0aa236b4}, {0x4d50c7537562033f, 0x57dc7625b61dfe89}, {0x45504801e0e6066b, 0x86e6c6d6152a3d04},
	{0xf13bc2d9c2fe222e, 0xbe4ccec9a6cdccfd}, {0x3752b423073b119a, 0x377dc5eb7c662bdb}, {0xebdbb918eb6d837f, 0x8fb5f218dd84147c},
	{0xf1b9b413df9d79ed, 0xa7621b6fd02db503}, {0xa53a6b64b1ac85c9, 0xd50e7f86ee1b832b}, {0xdbfaae9642b3205a, 0xf676a1339402bcb9},
	{0x47418a71800334a0, 0xd10395d8fc64d8a4}, {0xcaa33cf9b4f6619c, 0xb2c8648ad49c209f}, {0x941f5023c0c943f9, 0xdfdeb9564fd66f24},
	{0x7e7f61684080106, 0x837ace9794582976}, {0x272d8dd74f3006cc, 0xec6c2ad1ec03f554}, {0x7b2271a7a3248e22, 0x3b4f700e5a0ba523},
	{0x3f1229f4d0fd96fb, 0x33130aa5fa9d43f2}, {0x7d3e82d5ba29a90d, 0xd5983cc93a9d126a}, {0x1f3dcdfa513512d6, 0x4dc7ec07283117e4},
	{0xb3b782ad308f21ed, 0x4f2676485041dee0}, {0x44d68afda9568f08, 0x478568ed51ca1d65}, {0xc3314e362764ddb8, 0x6481c084ee9ec6b5},
	{0x2c6aa706129cc54c, 0x17a706f59a49f086}, {0xfc3e3c322cd5d89b, 0xb7e3911dc2bd4ebb}, {0x914f1ea2fdcebf5c, 0x9566453c07cd0601},
	{0x99468a917986162b, 0x7b31434aac6e0af0}, {0x8799e4740e573c50, 0x9e739b52d0f341e8}, {0x8063d80ab26f3d6d, 0x4177b4b9b4f0393f},
	{0x52c44837aa6dfc77, 0x15d8d8fccdd6dc5b}, {0xc791b313aba3f258, 0x443c7757a4727bee}, {0xbc241579d8348401, 0x16dc832804d728f0},
	{0x4283001239888836, 0xf44ca39a6f79db89}, {0x374dd4288e0b72e5, 0xff8916db706c0df4}, {0x9136456740119815, 0x4d8ff7733b27eb83},
	{0x14cf7f02dab0eee8, 0x6d01750605e89445}, {0x570d62758ddf6397, 0x5e0204fb68a7b800}, {0xc738a77a9a55f0e2, 0x705221addedd81df},
	{0x9b82567ab6560796, 0x891b69462b41c224}, {0x3c13e894365dc6c2, 0x26fc7bbcda3f0ef}, {0x6e65ec14a8fb565, 0x34bff6f2ee5a7f79},
	{0x379f76458a3c8957, 0x79dd080f9843af77}, {0x1e6f0910c3d25bd8, 0xad9e250862102467}, {0xb1cf09b0184a4834, 0x5c03db48eb6cc159},
	{0xceaf1a0d15234f15, 0x1450a54e45ba9b9}, {0x85b8e53f22e19507, 0xbb57137739ca486b}, {0xadc52dddb76f6e5e, 0x4aad4e925a962b68},
	{0xce030d15b5fe2f4, 0x86b4a7a0780c2431}, {0x64fd1bc011e5bab7, 0x5c9e858728015568}, {0xfdfa836b41dcef62, 0x2f8db8030e847e1b},
	{0x7d222caae025158a, 0xcc028d5fd40241b9}, {0x80395e48739e1a67, 0x74a67d8f7f43c3d7}, {0x133b299a939745c5, 0x796e2aac053f52b3},
	{0xfd1a9ba5e71b08a2, 0x7ac0dc2ed7778533}, {0x938f5bbab544d3d6, 0xd2a95f9f2d376d73}, {0xeea5f5a9f74af591, 0x578710bcc36fbea2},
	{0x2b826f1a2c08c289, 0xda50f56863b55e74}, {0xeffc2663cffc777f, 0x93214f8f463afbed}, {0x5a4fc2728a9bb671, 0xebb971522ec38759},
	{0xe777b1fd580582f2, 0x7b880f58da112699}, {0xdd16cd0fbc08393, 0x29a414a5d8c58962}, {0x4260e8c254e9924b, 0xf197a6eb4591572d},
	{0x4890a83ee435bc8b, 0xd8c1c00fceb00914}, {0x8ba0fdd2ffc8b239, 0xf413b366c1ffe02f}, {0xcf1edbfe7330e94e, 0x881945906bcb3cc6},
	{0xf6521b912b368ae6, 0xa9fe4eff81d03e73}, {0x6b5ffc1f54fecb29, 0xa8e8e7ad5b9a21d9}, {0x381ee1b7ea534f4e, 0xda3759828e3de429},
	{0x4cc8ed3ada5f0f2, 0x4a496b77c1f1c04e}, {0xe5d0549802d15008, 0x424c134ecd0db834}, {0xaa0d74d4a98db89b, 0x36fd486d07c56e1d},
	{0x28ac84ca70958f7e, 0xd8ae575a68faa731}, {0x43505ed133be672a, 0xe8f2f9d973c2774e}, {0x4344a1a0134afe2, 0xff5c17f02b62341d},
	{0x489b697fe30aa65f, 0x4da0fb621fdc7817}, {0xc043e67e6fc64118, 0xff0abfe926d844d3}, {0x334c5a25b5903a8c, 0x4c94fef443122128},
	{0x8bde625a10a8c50d, 0xeb8271ded1f79a0b}, {0xdd52fc14c8dd3143, 0x1bc7508516e40628}, {0xc1336b92fef91bf6, 0x80332a3945f33fa9},
	{0x497cb912b670f3b, 0xd963a3f02ff4a5b6}, {0x2fe9fabdbe7fdd4, 0x755db249a2d81a69}, {0xd53fb7e3c93a9e4, 0x737ae71b051bf108},
	{0xcf7d7f25bd70cd2c, 0x9464ed9baeb41b4f}, {0x9040e5b936b8661b, 0x276e08fa53ac27fd}, {0x8431b1bfd0a2379c, 0x90383913aea283f9},
	{0xc54677a80367125e, 0x3204fbdba462e606}, {0x9598f6ab0683fcc2, 0x1c805abf7b80e1ee}, {0x6ba372f4b7ab268b, 0x8c3237cf1fe243df},
	{0x9a62af3dbba140da, 0x27857ea044e9dfc1}, {0x82065c62e6582188, 0x8ef787fd356f5e43}, {0x22f2aa3df2221cc, 0xf66fea90f5d62174},
	{0x229b79ab69ae97d, 0xa87aabc2ec26e582}, {0xd332cdb073d8dc46, 0x272c56466868cb46}, {0x702e2afc7f5a1825, 0x8c49b11ea8151fdc},
	{0xa590b202a7a5807b, 0x968d2593f7ccb54e}, {0x7432d63888e0c306, 0x74bbceeed479cb71}, {0x69db23875cb0b715, 0xada8dd91504ae37f},
	{0xc4af7faf883033aa, 0x9bd296c4e9453cac}, {0x42e34cf3d53c7876, 0x9cddbb26424dc5e}, {0xbcc7a81ed5432429, 0xb6d7bdc6ad2e81f1},
	{0x6226a32e25099848, 0xea895661ecf53004}, {0xca6552a0dfb82c73, 0xb024cdf09e34ba07}, {0xf14ef7f47d8a57a3, 0x80d1f86f2e061d7c},
	{0xc8389799445480db, 0x5389f5df8aacd50d}, {0x70bd1968996bffc2, 0x4c613de5d8ab32ac}, {0x8eeb177a86053c11, 0xe390122c345f34a2},
	{0x27233b28b5b11e9b, 0xc7dfe8988a942700}, {0x49fa3070bc7b06d0, 0xf12ed446bd0c0539}, {0x57466046cf6896ed, 0x8ac37e0e8b25b0c6},
	{0xc2dcc9758c910171, 0xcb5cddaeff4ddb40}, {0x3ee84d3d5b4ca00b, 0x5cbc6d701894c3f9}, {0x6b11c5073687208, 0x7e0a57de0d453f3},
	{0x7da9e81d89fda7ad, 0x274157cabe71440d}, {0xd45a938b79f54e8f, 0x366b219d6d133e48}, {0xc83d3c5f4e5f0320, 0x694e7adeb2bf32e5},
	{0xbc271bc0df14d647, 0xb071100a9ff2edbb}, {0x336c1b59a1fc19f6, 0xc173acaecc471305}, {0x84064a6dcf916340, 0xfbf55a26790e0ebb},
	{0xe38e526cd3324364, 0x85f2b63a5b5e840a}, {0x16818ee9d38c6664, 0x5519fa9a1e35a329}, {0x30278016830ddd43, 0xf046646d9012e074},
	{0x7d2782b82bd494b6, 0x97159ba1c26b304b}, {0x58c8aba7475e2d95, 0x3e2f291698c9427a}, {0xd1090893afaab8bc, 0x96c4fe6922772807},
	{0xfc947167f69c0da5, 0xae79cfdb91b6f6c1}, {0xb7609c8e70386d66, 0x36e6ccc278d1636d}, {0x4c10537443152f3d, 0x720451d3c895e25d},
	{0xf265edb0c1c411d7, 0x30e1e9ec5262b7e6}, {0xe9369d2e9007e74b, 0xb1375915d1136052}, {0x301d7a61c4b3dbca, 0x861336c3f0552d61},
	{0x6cef866ec295abea, 0xc486c0d9214beb2d}, {0xfcfb9443e997cab, 0xf13310d96dec2772}, {0x73119c99e6d508be, 0x5d4036a187735385},
	{0xaafcb77497b5a20b, 0x411819e5e79b77a3}, {0x3f44f873be4812ec, 0x427662c1dbfaa7b2}, {0xd396a297799c24a1, 0x8fee992e3069bad5},
	{0x895fe8443183da74, 0xc7f2f6f895a67334}, {0xa3d5d1137d30c4bd, 0x1e7d706a49bdfb9e}, {0xb22bf08d9f8aecf7, 0xc182730de337b922},
	{0x882efc2561715a9c, 0xef8132a18a540221}, {0x371a98b2cb084883, 0x33a2886ee9f00663}, {0x89f3aab99afbd636, 0xf420e004f8148b9a},
	{0x21c2be098327f49b, 0x7e035065ac7bbef5}, {0x9d097dd3152ab107, 0x51e21d24126e8563}, {0xc1a78b82ba815b74, 0x458cbdfc82eb322a},
	{0x5aeead8d6cb25bb9, 0x739315f7743ec3ff}, {0xba1ffba29f0367aa, 0xa20bec1dd15a8b6c}, {0xd8ad7ec84a9c9aa2, 0xe256cffed11f69e6},
	{0x361e0a62c8187bff, 0x6089971bb84d7133}, {0x4ec02f3d2f2b23f2, 0xab3580708aa7c339}, {0xc2c9fc637dbdfcfa, 0x292ab8306d149d75},
	{0xe1a8286a7d67946e, 0x52bd956f047b298}, {0xbde51033ac0413f8, 0xbc0272f691aec629}, {0x6c71064996cbec8b, 0x352c535edeefcb89},
	{0x43e47bd5bab1e0ef, 0x4a71f363421f282f}, {0x832954ec9d0de333, 0x94c390aa9bcb6b8a}, {0x4960111789727567, 0x149b8a37c7125ab6},
	{0x6566d74954986ba5, 0x99d5235cc82519a7}, {0xc8a2827404991402, 0x7ee5e78550f02675}, {0x3edbc10e4bfee91b, 0xf0d681304c28ef68},
	{0x83707730cad725d4, 0xc9ca88c3a779674a}, {0x1ef8e98e1ea57269, 0x5971116272f45a8b}, {0x3eeb60c3f5f8143d, 0xa25aec05c422a24f},
	{0x36a8d13a2cbb0939, 0x254ac73907413230}, {0x5b2b7ca856fad1c3, 0x8093022d682e375d}, {0x48b218e3b721810d, 0xd3757ac8609bc7fc},
	{0x15747d8c505ffd00, 0x438a15f391312cd6}, {0xd9ccef1d4be46988, 0x5ede0c4e383a5e66}, {0x2870a99c76a587a4, 0x99f74cc0b182dda4},
	{0xa3335c417687cf3a, 0x92ff114ac45cda75}, {0xc7cd48f7abf1fe59, 0xce600656ace6f53a}, {0xd803e1eead47604c, 0xad00f7611970a71b},
	{0xd17c928c5342477f, 0x745130b795254ad5}, {0x6531c1fe32bcb417, 0x8c970d8df8cdbeb4}, {0xffe319654c8e7ebc, 0x6a67b8f13ead5a72},
	{0x8950cfcf4bdf622c, 0x8847dca82efeef2f}, {0x14453b5cc3d82396, 0x4ef700c33ed278bc}, {0x276aa37744b5a028, 0x8c10800ee90ea573},
	{0xff5c03f003c1fefe, 0xe1098670afe7ff6}, {0xe2164451c651adfb, 0xb2534e65477f9823}, {0xad159f542d81f04e, 0x49626a97a946096},
	{0x3712eb913d04e2f2, 0x2f9500d319c84d89}, {0xa3c1c5ca1b0367, 0xeb6933997272bb3d}, {0x5aa82bfaa99d3978, 0xc18f96cade5ce18d},
	{0x8b305d532e61226e, 0xcaeae80da2ea2e}, {0x751390a8a5c41bdc, 0x6ee5fbf87605d34}, {0xb87a326e413604bf, 0xd8f9a5fa214b03ab},
	{0x5df25f13ea7bc284, 0x165edfaafd2598fb}, {0x58eb4d03b2c3ddf5, 0x6d2542995f9189f1}, {0x7f759dddc6e8549a, 0x616dd0ca022c8735},
	{0xf271ba474edc562d, 0xe6596e67f9dd3ebd}, {0x45744afcf131dbee, 0x97222392c2559350}, {0xb6dd09ba7851c7af, 0x570de4e1bb13b133},
	{0x216e1d6c86cb524c, 0xd01cf6fd4f4065c0}, {0xbceee07c11a9ac30, 0x2e2d47dff8e77eb7}, {0xbd2b31b5608143fe, 0xab717a10f2554853},
	{0xb9e0d415b4ebd534, 0xc97c2a27efaa33d7}, {0x2228d6725e31b8ab, 0x9b98f7e4d0142e70}, {0x87049e68f5d38e59, 0x7d8ce44ec6bd7751},
	{0x98d0dbf796480187, 0xfbcb5f3e1bef5742}, {0x57c5208e8f021a77, 0xf7653fbb69cd9276}, {0x68110a7f83f5d3ff, 0x6d77e045901b85a8},
	{0xd1bfe4df12b04cbf, 0xf58c17243fd63842}, {0x61c9c95d91017da5, 0x16f7c83ba68f5279}, {0x58634004c7b2d19a, 0x24bb5f51ed3b9073},
	{0x29c3529eb165eeba, 0x443de3703b657c35}, {0xae59ca86f4c3323d, 0x25906c09906d5c4c}, {0xd4edc954c07cd8f3, 0x224f47e7c00a30ab},
	{0xb1b7ec44f9302176, 0x5cb476450dc0c297}, {0x54bc9bee7cbe1767, 0x485820bdbe442431}, {0x80973ea532b0f310, 0xa471829aa9c17dd9},
	{0x230d2b3e47f09830, 0xec8624a821c1caf4}, {0x7122413bdbc94035, 0xe7f90fae33bf7763}, {0x5ed12338f630ab76, 0xfab19fcb319116d},
	{0xfca4e5bc9292788e, 0xcd509dc1facce41c}, {0x967e970df9673d2a, 0xd465247cffa415c0}, {0x6cc09e60700563e9, 0xd18f23221e964791},
}

func TestCityHash128(t *testing.T) {
	data := generateTestData()
	for i, expected := range testcases {
		u := Sum128(data[i])
		assertEqual(t, expected[0], u.Lower64())
		assertEqual(t, expected[1], u.Higher64())
	}
}
