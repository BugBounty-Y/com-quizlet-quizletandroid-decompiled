package com.pubmatic.sdk.video.xmlserialiser;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import java.io.StringReader;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

/* loaded from: classes2.dex */
public abstract class c {
    @NonNull
    public static Node createNode(@NonNull String str) throws Exception {
        Element documentElement = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(str))).getDocumentElement();
        documentElement.normalize();
        return documentElement;
    }

    public static <T extends b> T parse(@NonNull String str, @NonNull Class<T> cls) throws IllegalAccessException, InstantiationException {
        try {
            Node nodeCreateNode = createNode(str);
            T tNewInstance = cls.newInstance();
            tNewInstance.build(new a(nodeCreateNode));
            return tNewInstance;
        } catch (Exception e) {
            POBLog.error("POBXMLParser", e.getMessage(), new Object[0]);
            return null;
        }
    }
}
