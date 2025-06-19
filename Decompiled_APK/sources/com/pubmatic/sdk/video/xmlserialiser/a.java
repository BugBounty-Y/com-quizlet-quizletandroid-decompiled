package com.pubmatic.sdk.video.xmlserialiser;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.ArrayList;
import java.util.List;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/* loaded from: classes2.dex */
public class a {
    private Node a;

    public a(Node node) {
        this.a = node;
    }

    private NodeList a(@NonNull String str) {
        try {
            return (NodeList) XPathFactory.newInstance().newXPath().compile(str).evaluate(this.a, XPathConstants.NODESET);
        } catch (Exception e) {
            POBLog.error("POBNodeBuilder", e.getMessage(), new Object[0]);
            return null;
        }
    }

    public String getAttributeValue(@NonNull String str) {
        Node node = getNode("@" + str);
        if (node != null) {
            return node.getTextContent().trim();
        }
        return null;
    }

    public Node getNode(@NonNull String str) {
        try {
            return (Node) XPathFactory.newInstance().newXPath().compile(str).evaluate(this.a, XPathConstants.NODE);
        } catch (Exception e) {
            POBLog.error("POBNodeBuilder", e.getMessage(), new Object[0]);
            return null;
        }
    }

    public String getNodeName() {
        Node node = this.a;
        if (node != null) {
            return node.getNodeName();
        }
        return null;
    }

    public <T extends b> T getNodeObject(@NonNull String str, @NonNull Class<T> cls) throws IllegalAccessException, InstantiationException {
        Node node = getNode(str);
        if (node != null) {
            try {
                T tNewInstance = cls.newInstance();
                tNewInstance.build(new a(node));
                return tNewInstance;
            } catch (Exception e) {
                POBLog.error("POBNodeBuilder", e.getMessage(), new Object[0]);
            }
        }
        return null;
    }

    public String getNodeValue() {
        Node node = this.a;
        if (node == null || node.getTextContent().isEmpty()) {
            return null;
        }
        return this.a.getTextContent().trim();
    }

    public <T extends b> List<T> getObjectList(@NonNull String str, @NonNull Class<T> cls) throws IllegalAccessException, InstantiationException {
        NodeList nodeListA = a(str);
        if (nodeListA == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < nodeListA.getLength(); i++) {
            Node nodeItem = nodeListA.item(i);
            if (nodeItem != null) {
                try {
                    T tNewInstance = cls.newInstance();
                    tNewInstance.build(new a(nodeItem));
                    arrayList.add(tNewInstance);
                } catch (Exception e) {
                    POBLog.error("POBNodeBuilder", e.getMessage(), new Object[0]);
                    return null;
                }
            }
        }
        return arrayList;
    }

    public List<String> getStringList(@NonNull String str) {
        NodeList nodeListA = a(str);
        if (nodeListA == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < nodeListA.getLength(); i++) {
            Node nodeItem = nodeListA.item(i);
            if (nodeItem != null) {
                arrayList.add(nodeItem.getTextContent().trim());
            }
        }
        return arrayList;
    }

    public String getNodeValue(@NonNull String str) {
        Node node = getNode(str);
        if (node != null) {
            return node.getTextContent().trim();
        }
        return null;
    }
}
