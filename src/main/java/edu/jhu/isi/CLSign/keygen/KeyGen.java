package edu.jhu.isi.CLSign.keygen;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.util.List;
import java.util.stream.Collectors;

public class KeyGen {
    public static PublicKey createPublicKey(final Pairing pairing, final PairingParameters params, final SecretKey sk) {
        final Element generator = pairing.getG1().newRandomElement().getImmutable();
        final Element X = generator.powZn(sk.getX());
        final Element Y = generator.powZn(sk.getY());
        final List<Element> Z = sk.getZ().stream()
                .map(generator::powZn).collect(Collectors.toList());
        final List<Element> W = sk.getZ().stream()
                .map(Y::powZn).collect(Collectors.toList());
        return new PublicKey(pairing, params, generator, X, Y, Z, W);
    }

    public static SecretKey createSecretKey(final Pairing pairing, final int messageSize) {
        final ZrElement[] z = new ZrElement[messageSize];
        for (int i = 0; i < messageSize; i++) {
            z[i] = (ZrElement) pairing.getZr().newRandomElement().getImmutable();
        }
        return new SecretKey((ZrElement) pairing.getZr().newRandomElement().getImmutable(),
                (ZrElement) pairing.getZr().newRandomElement().getImmutable(), z);
    }

    public static Pairing createPairing() {
        int rBits = 160;
        int qBits = 512;

        final TypeACurveGenerator pairingGenerator = new TypeACurveGenerator(rBits, qBits);
        final PairingParameters params = pairingGenerator.generate();
        return PairingFactory.getPairing(params);
    }

    public static PairingParameters createPairingParams() {
        int rBits = 160;
        int qBits = 512;

        final TypeACurveGenerator pairingGenerator = new TypeACurveGenerator(rBits, qBits);
        final PairingParameters params = pairingGenerator.generate();
        return params;
    }

    public static  Pairing getPairing(PairingParameters params) {
        return PairingFactory.getPairing(params);
    }
}
