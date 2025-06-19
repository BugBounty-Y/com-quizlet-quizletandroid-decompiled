package com.google.protobuf;

/* loaded from: classes2.dex */
public final class J implements Q {
    public Q[] a;

    @Override // com.google.protobuf.Q
    public final C4007b0 a(Class cls) {
        for (Q q : this.a) {
            if (q.b(cls)) {
                return q.a(cls);
            }
        }
        throw new UnsupportedOperationException("No factory is available for message type: ".concat(cls.getName()));
    }

    @Override // com.google.protobuf.Q
    public final boolean b(Class cls) {
        for (Q q : this.a) {
            if (q.b(cls)) {
                return true;
            }
        }
        return false;
    }
}
