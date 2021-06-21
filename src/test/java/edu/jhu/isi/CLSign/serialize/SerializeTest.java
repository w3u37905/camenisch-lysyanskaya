package edu.jhu.isi.CLSign.serialize;

import edu.jhu.isi.CLSign.CLSign;
import edu.jhu.isi.CLSign.keygen.KeyPair;
import edu.jhu.isi.CLSign.keygen.PublicKey;
import edu.jhu.isi.CLSign.keygen.SecretKey;
import it.unisa.dia.gas.jpbc.Pairing;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SerializeTest {

    @Test
    public void testSerializeSecretKey() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final PublicKey pk = keyPair.getPk();
        final SecretKey sk = keyPair.getSk();
        final Pairing pairing = pk.getPairing();
        final byte[] skBytes = Serialize.serializeSecretKey(sk, pairing);
        final SecretKey deserializedSk = Serialize.deserializeSecretKey(skBytes, pairing);
        assertNotNull(pk);
        assertNotNull(deserializedSk);
        assertEquals(messageSize, deserializedSk.getZ().size());
        assertEquals(messageSize, pk.getZ().size());
        assertEquals(messageSize, pk.getW().size());
        assertEquals(pk.getGenerator().powZn(deserializedSk.getX()), pk.getX());
        assertEquals(pk.getGenerator().powZn(deserializedSk.getY()), pk.getY());
        for (int i = 0; i < messageSize; i++) {
            assertEquals(pk.getGenerator().powZn(deserializedSk.getZ(i)), pk.getZ(i));
            assertEquals(pk.getY().powZn(deserializedSk.getZ(i)), pk.getW(i));
        }
        assertEquals(pk.getPairing().getG1(), pk.getPairing().getG2());
    }

    @Test
    public void testSerializePublicKey() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final PublicKey pk = keyPair.getPk();
        final SecretKey sk = keyPair.getSk();
        final Pairing pairing = pk.getPairing();
        final byte[] pkBytes = Serialize.serializePublicKey(pk);
        final PublicKey deserializedPk = Serialize.deserializePublicKey(pkBytes);
        assertNotNull(deserializedPk);
        assertNotNull(sk);
        assertEquals(messageSize, sk.getZ().size());
        assertEquals(messageSize, deserializedPk.getZ().size());
        assertEquals(messageSize, deserializedPk.getW().size());
        assertEquals(deserializedPk.getGenerator().powZn(sk.getX()), deserializedPk.getX());
        assertEquals(deserializedPk.getGenerator().powZn(sk.getY()), deserializedPk.getY());
        for (int i = 0; i < messageSize; i++) {
            assertEquals(deserializedPk.getGenerator().powZn(sk.getZ(i)), deserializedPk.getZ(i));
            assertEquals(deserializedPk.getY().powZn(sk.getZ(i)), deserializedPk.getW(i));
        }
        assertEquals(deserializedPk.getPairing().getG1(), deserializedPk.getPairing().getG2());

    }




}
