rule DetectBitcoinAddress
{
    meta:
        description = "Detecte les adresses Bitcoin potentielles"
        author = "Cyrill Gremaud"
        date = "2023-09-23"

    strings:
        $btc_p2pkh = /\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b/
        $btc_p2sh = /\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b/
        $btc_bech32 = /\bbc1[qrpzry9x8gf2tvdw0s3jn54khce6mua7l]{14,74}\b/

    condition:
        $btc_p2pkh or $btc_p2sh or $btc_bech32
}