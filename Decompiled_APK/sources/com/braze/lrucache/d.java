package com.braze.lrucache;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;

/* loaded from: classes.dex */
public final class d {
    public final g a;
    public final boolean[] b;
    public boolean c;
    public final /* synthetic */ f d;

    public d(f fVar, g gVar) {
        this.d = fVar;
        this.a = gVar;
        this.b = gVar.c ? null : new boolean[fVar.g];
    }

    public final OutputStream a() {
        FileOutputStream fileOutputStream;
        c cVar;
        f fVar = this.d;
        if (fVar.g <= 0) {
            throw new IllegalArgumentException("Expected index 0 to be greater than 0 and less than the maximum value count of " + this.d.g);
        }
        synchronized (fVar) {
            try {
                g gVar = this.a;
                if (gVar.d != this) {
                    throw new IllegalStateException();
                }
                if (!gVar.c) {
                    this.b[0] = true;
                }
                File fileA = gVar.a(0);
                try {
                    fileOutputStream = new FileOutputStream(fileA);
                } catch (FileNotFoundException unused) {
                    this.d.a.mkdirs();
                    try {
                        fileOutputStream = new FileOutputStream(fileA);
                    } catch (FileNotFoundException unused2) {
                        return f.q;
                    }
                }
                cVar = new c(this, fileOutputStream);
            } catch (Throwable th) {
                throw th;
            }
        }
        return cVar;
    }
}
