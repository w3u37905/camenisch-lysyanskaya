package edu.jhu.isi.CLSign.serialize;

import edu.jhu.isi.CLSign.keygen.KeyGen;
import edu.jhu.isi.CLSign.keygen.PublicKey;
import edu.jhu.isi.CLSign.keygen.SecretKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class Serialize {

//---------- Secret Key ----------------------------------------------------------
    public static byte[] serializeSecretKey(final SecretKey sk, final Pairing pairing) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream writer = new DataOutputStream(baos);
        // write...
        writeElement(writer, sk.getX(), pairing);
        writeElement(writer, sk.getY(), pairing);
        writer.writeInt(sk.getZ().size());
        for(ZrElement zi : sk.getZ()) {
            writeElement(writer, zi, pairing);
        }
        //----------------
        writer.flush();
        byte[] result = baos.toByteArray();
        return result;
    }

    public static SecretKey deserializeSecretKey(final byte[] skBytes, final Pairing pairing) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bais = new ByteArrayInputStream(skBytes);
        DataInputStream reader = new DataInputStream(bais);
        // read..
        ZrElement x = (ZrElement)readElement(reader, pairing);
        ZrElement y = (ZrElement)readElement(reader, pairing);
        int messageSize = reader.readInt();
        final ZrElement[] z = new ZrElement[messageSize];
        for(int i=0; i<messageSize; i++) {
            z[i] = (ZrElement)readElement(reader, pairing);
        }
        return new SecretKey(x,y,z);
    }
//------------------------------------------------------------------------------------
//---------- Public Key --------------------------------------------------------------
    public static byte[] serializePublicKey(final PublicKey pk) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream writer = new DataOutputStream(baos);
        // write...

        //write pairing parameters
        Pairing pairing = pk.getPairing();
        byte[] params = SerializationUtils.convertToBytes(pk.getParameters());
        writer.writeInt(params.length);
        writer.write(params);

        writeElement(writer, pk.getGenerator(), pairing);
        writeElement(writer, pk.getX(), pairing);
        writeElement(writer, pk.getY(), pairing);
        writeElements(writer, pk.getZ(), pairing);
        writeElements(writer, pk.getW(), pairing);
        //----------------
        writer.flush();
        byte[] result = baos.toByteArray();
        return result;
    }

    public static PublicKey deserializePublicKey(final byte[] pkBytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bais = new ByteArrayInputStream(pkBytes);
        DataInputStream reader = new DataInputStream(bais);
        // read..

        //deserialize pairing parameters and get Pairing
        int length = reader.readInt();
        byte[] bytes = new byte[length];
        reader.readFully(bytes);
        PairingParameters params = (PairingParameters)SerializationUtils.convertFromBytes(bytes);
        Pairing pairing = KeyGen.getPairing(params);

        Element generator = readElement(reader, pairing);
        Element X = readElement(reader, pairing);
        Element Y = readElement(reader, pairing);
        List<Element> Z = readElements(reader, pairing);
        List<Element> W = readElements(reader, pairing);

        return new PublicKey(pairing,params, generator, X, Y, Z, W);
    }
    //------------------------------------------------------------------------------------
    private static Element readElement(DataInputStream reader, Pairing pairing) throws IOException {
        int fieldIndex = reader.readInt();
        int length = reader.readInt();
        byte[] bytes = new byte[length];
        reader.readFully(bytes);
        Element e = (Element) pairing.getFieldAt(fieldIndex)
                .newElementFromBytes(bytes)
                .getImmutable();
        return e;
    }

    private static List<Element> readElements(DataInputStream reader, Pairing pairing) throws IOException {
        int messageSize = reader.readInt();
        List<Element> elements = new ArrayList<>();
        for(int i=0; i<messageSize; i++) {
            Element element = readElement(reader, pairing);
            elements.add(element);
        }
        return elements;
    }

    private static void writeElement(final DataOutputStream writer,
                                     final Element element,
                                     final Pairing pairing) throws IOException {
        int fieldIndex = pairing.getFieldIndex(element.getField());
        writer.writeInt(fieldIndex);
        byte[] xBytes = element.toBytes();
        writer.writeInt(xBytes.length);
        writer.write(xBytes);
    }

    private static void writeElements(DataOutputStream writer, List<Element> elements, Pairing pairing) throws IOException {
        writer.writeInt(elements.size());
        for(Element e : elements) {
            writeElement(writer, e, pairing);
        }
    }


}
