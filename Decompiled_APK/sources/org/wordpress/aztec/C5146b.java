package org.wordpress.aztec;

import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.AttributesImpl;

/* renamed from: org.wordpress.aztec.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5146b extends AttributesImpl {
    public /* synthetic */ C5146b() {
        this(new AttributesImpl());
    }

    public final boolean a(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return getValue(key) != null;
    }

    public final void b() {
        org.wordpress.android.util.a.b("Dumping internal state:");
        org.wordpress.android.util.a.b("length = " + getLength());
        try {
            org.wordpress.android.util.a.b(toString());
        } catch (ArrayIndexOutOfBoundsException unused) {
        }
    }

    public final void c(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        if (a(key)) {
            int index = getIndex(key);
            try {
                removeAttribute(index);
            } catch (ArrayIndexOutOfBoundsException e) {
                org.wordpress.android.util.a.b("Tried to remove attribute: " + key + " that is not in the list");
                StringBuilder sb = new StringBuilder("Reported to be at index: ");
                sb.append(index);
                org.wordpress.android.util.a.b(sb.toString());
                b();
                throw e;
            }
        }
    }

    /* JADX WARN: Unreachable blocks removed: 2, instructions: 4 */
    public final void d(String key, String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        int index = getIndex(key);
        if (index != -1) {
            setValue(index, value);
            return;
        }
        try {
            addAttribute("", key, key, "string", value);
        } catch (ArrayIndexOutOfBoundsException e) {
            org.wordpress.android.util.a.b("Error adding attribute with name: " + key + " and value: " + value);
            b();
            throw e;
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        try {
            int length = getLength() - 1;
            if (length >= 0) {
                int i = 0;
                while (true) {
                    sb.append(getLocalName(i));
                    sb.append("=\"");
                    sb.append(getValue(i));
                    sb.append("\" ");
                    if (i == length) {
                        break;
                    }
                    i++;
                }
            }
            return StringsKt.h0(sb).toString();
        } catch (ArrayIndexOutOfBoundsException e) {
            org.wordpress.android.util.a.b("IOOB occurred in toString. Dumping partial state:");
            org.wordpress.android.util.a.b(StringsKt.h0(sb).toString());
            throw e;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5146b(Attributes attributes) {
        super(attributes);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
    }
}
