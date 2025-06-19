package com.google.firebase.crashlytics.internal.metadata;

import java.io.IOException;

/* loaded from: classes2.dex */
public final class f implements k {
    public static final com.quizlet.shared.usecase.folderstudymaterials.a c = new com.quizlet.shared.usecase.folderstudymaterials.a(18);
    public final Object a;
    public Object b;

    public f(com.google.firebase.crashlytics.internal.persistence.c cVar) {
        this.a = cVar;
        this.b = c;
    }

    @Override // com.google.firebase.crashlytics.internal.metadata.k
    public void a(j jVar, int i) throws IOException {
        int[] iArr = (int[]) this.b;
        try {
            jVar.read((byte[]) this.a, iArr[0], i);
            iArr[0] = iArr[0] + i;
        } finally {
            jVar.close();
        }
    }

    public f(byte[] bArr, int[] iArr) {
        this.a = bArr;
        this.b = iArr;
    }
}
