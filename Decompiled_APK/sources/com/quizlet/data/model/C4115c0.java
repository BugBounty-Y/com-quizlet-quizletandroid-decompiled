package com.quizlet.data.model;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.c0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4115c0 {
    public final String a;
    public final File b;

    public C4115c0(File file, String filename) {
        Intrinsics.checkNotNullParameter(filename, "filename");
        Intrinsics.checkNotNullParameter("image[]", "name");
        Intrinsics.checkNotNullParameter("image/*", "mimeType");
        Intrinsics.checkNotNullParameter(file, "file");
        this.a = filename;
        this.b = file;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4115c0)) {
            return false;
        }
        C4115c0 c4115c0 = (C4115c0) obj;
        return Intrinsics.b(this.a, c4115c0.a) && this.b.equals(c4115c0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (((((this.a.hashCode() * 31) + 1911933437) * 31) + 1911932022) * 31);
    }

    public final String toString() {
        return "FileUploadSpec(filename=" + this.a + ", name=image[], mimeType=image/*, file=" + this.b + ")";
    }
}
