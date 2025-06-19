package kotlin.jvm.internal;

import java.io.ObjectStreamException;
import java.io.Serializable;

/* renamed from: kotlin.jvm.internal.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4945d implements Serializable {
    public static final C4945d a = new C4945d();

    private Object readResolve() throws ObjectStreamException {
        return a;
    }
}
