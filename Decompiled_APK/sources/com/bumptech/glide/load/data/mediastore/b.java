package com.bumptech.glide.load.data.mediastore;

import android.content.Context;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import com.bumptech.glide.Glide;
import com.bumptech.glide.g;
import com.bumptech.glide.load.data.e;
import com.bumptech.glide.load.model.C1535c;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes.dex */
public final class b implements e {
    public final /* synthetic */ int a;
    public final Comparable b;
    public final Object c;
    public Object d;

    public /* synthetic */ b(int i, Comparable comparable, Object obj) {
        this.a = i;
        this.b = comparable;
        this.c = obj;
    }

    public static b a(Context context, Uri uri, c cVar) {
        return new b(0, uri, new d(Glide.a(context).c.a().e(), cVar, Glide.a(context).d, context.getContentResolver()));
    }

    private final void b() {
    }

    private final void c() {
    }

    private final void d() {
    }

    @Override // com.bumptech.glide.load.data.e
    public final void cancel() {
        int i = this.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0029 A[PHI: r5
  0x0029: PHI (r5v11 android.database.Cursor) = (r5v2 android.database.Cursor), (r5v13 android.database.Cursor) binds: [B:20:0x003b, B:11:0x0027] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0046  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00b5  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x008c A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:79:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.InputStream e() throws java.lang.Throwable {
        /*
            r12 = this;
            java.lang.String r0 = "ThumbStreamOpener"
            java.lang.Comparable r1 = r12.b
            android.net.Uri r1 = (android.net.Uri) r1
            java.lang.Object r2 = r12.c
            com.bumptech.glide.load.data.mediastore.d r2 = (com.bumptech.glide.load.data.mediastore.d) r2
            r3 = 3
            r4 = 0
            com.bumptech.glide.load.data.mediastore.c r5 = r2.a     // Catch: java.lang.Throwable -> L2e java.lang.SecurityException -> L31
            android.database.Cursor r5 = r5.a(r1)     // Catch: java.lang.Throwable -> L2e java.lang.SecurityException -> L31
            if (r5 == 0) goto L27
            boolean r6 = r5.moveToFirst()     // Catch: java.lang.Throwable -> L23 java.lang.SecurityException -> L32
            if (r6 == 0) goto L27
            r6 = 0
            java.lang.String r6 = r5.getString(r6)     // Catch: java.lang.Throwable -> L23 java.lang.SecurityException -> L32
            r5.close()
            goto L3e
        L23:
            r0 = move-exception
            r4 = r5
            goto Lbf
        L27:
            if (r5 == 0) goto L2c
        L29:
            r5.close()
        L2c:
            r6 = r4
            goto L3e
        L2e:
            r0 = move-exception
            goto Lbf
        L31:
            r5 = r4
        L32:
            boolean r6 = android.util.Log.isLoggable(r0, r3)     // Catch: java.lang.Throwable -> L23
            if (r6 == 0) goto L3b
            java.util.Objects.toString(r1)     // Catch: java.lang.Throwable -> L23
        L3b:
            if (r5 == 0) goto L2c
            goto L29
        L3e:
            boolean r5 = android.text.TextUtils.isEmpty(r6)
            android.content.ContentResolver r7 = r2.c
            if (r5 == 0) goto L48
        L46:
            r5 = r4
            goto L89
        L48:
            java.io.File r5 = new java.io.File
            r5.<init>(r6)
            boolean r6 = r5.exists()
            if (r6 == 0) goto L46
            long r8 = r5.length()
            r10 = 0
            int r6 = (r10 > r8 ? 1 : (r10 == r8 ? 0 : -1))
            if (r6 >= 0) goto L46
            android.net.Uri r5 = android.net.Uri.fromFile(r5)
            java.io.InputStream r5 = r7.openInputStream(r5)     // Catch: java.lang.NullPointerException -> L66
            goto L89
        L66:
            r0 = move-exception
            java.io.FileNotFoundException r2 = new java.io.FileNotFoundException
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            java.lang.String r4 = "NPE opening uri: "
            r3.<init>(r4)
            r3.append(r1)
            java.lang.String r1 = " -> "
            r3.append(r1)
            r3.append(r5)
            java.lang.String r1 = r3.toString()
            r2.<init>(r1)
            java.lang.Throwable r0 = r2.initCause(r0)
            java.io.FileNotFoundException r0 = (java.io.FileNotFoundException) r0
            throw r0
        L89:
            r6 = -1
            if (r5 == 0) goto Lb5
            java.io.InputStream r4 = r7.openInputStream(r1)     // Catch: java.lang.Throwable -> L9e java.lang.Throwable -> La0
            java.util.ArrayList r7 = r2.d     // Catch: java.lang.Throwable -> L9e java.lang.Throwable -> La0
            androidx.compose.foundation.lazy.grid.m r2 = r2.b     // Catch: java.lang.Throwable -> L9e java.lang.Throwable -> La0
            int r0 = com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z.a(r7, r4, r2)     // Catch: java.lang.Throwable -> L9e java.lang.Throwable -> La0
            if (r4 == 0) goto Lb6
            r4.close()     // Catch: java.io.IOException -> Lb6
            goto Lb6
        L9e:
            r0 = move-exception
            goto Laf
        La0:
            boolean r0 = android.util.Log.isLoggable(r0, r3)     // Catch: java.lang.Throwable -> L9e
            if (r0 == 0) goto La9
            java.util.Objects.toString(r1)     // Catch: java.lang.Throwable -> L9e
        La9:
            if (r4 == 0) goto Lb5
            r4.close()     // Catch: java.io.IOException -> Lb5
            goto Lb5
        Laf:
            if (r4 == 0) goto Lb4
            r4.close()     // Catch: java.io.IOException -> Lb4
        Lb4:
            throw r0
        Lb5:
            r0 = r6
        Lb6:
            if (r0 == r6) goto Lbe
            com.bumptech.glide.load.data.j r1 = new com.bumptech.glide.load.data.j
            r1.<init>(r5, r0)
            r5 = r1
        Lbe:
            return r5
        Lbf:
            if (r4 == 0) goto Lc4
            r4.close()
        Lc4:
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.load.data.mediastore.b.e():java.io.InputStream");
    }

    @Override // com.bumptech.glide.load.data.e
    public final void f() throws IOException {
        switch (this.a) {
            case 0:
                InputStream inputStream = (InputStream) this.d;
                if (inputStream != null) {
                    try {
                        inputStream.close();
                        break;
                    } catch (IOException unused) {
                        return;
                    }
                }
                break;
            case 1:
                try {
                    ((ByteArrayInputStream) this.d).close();
                    break;
                } catch (IOException unused2) {
                    return;
                }
            default:
                Object obj = this.d;
                if (obj != null) {
                    try {
                        switch (((C1535c) this.c).a) {
                            case 4:
                                ((ParcelFileDescriptor) obj).close();
                                break;
                            default:
                                ((InputStream) obj).close();
                                break;
                        }
                        break;
                    } catch (IOException unused3) {
                        return;
                    }
                }
                break;
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final int g() {
        switch (this.a) {
        }
        return 1;
    }

    @Override // com.bumptech.glide.load.data.e
    public final Class getDataClass() {
        switch (this.a) {
            case 0:
                return InputStream.class;
            case 1:
                ((C1535c) this.c).getClass();
                return InputStream.class;
            default:
                return ((C1535c) this.c).b();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final void h(g gVar, com.bumptech.glide.load.data.d dVar) throws Throwable {
        Object objOpen;
        switch (this.a) {
            case 0:
                try {
                    InputStream inputStreamE = e();
                    this.d = inputStreamE;
                    dVar.i(inputStreamE);
                    break;
                } catch (FileNotFoundException e) {
                    Log.isLoggable("MediaStoreThumbFetcher", 3);
                    dVar.a(e);
                    return;
                }
            case 1:
                try {
                    ByteArrayInputStream byteArrayInputStreamA = C1535c.a((String) this.b);
                    this.d = byteArrayInputStreamA;
                    dVar.i(byteArrayInputStreamA);
                    break;
                } catch (IllegalArgumentException e2) {
                    dVar.a(e2);
                    return;
                }
            default:
                try {
                    C1535c c1535c = (C1535c) this.c;
                    File file = (File) this.b;
                    switch (c1535c.a) {
                        case 4:
                            objOpen = ParcelFileDescriptor.open(file, 268435456);
                            break;
                        default:
                            objOpen = new FileInputStream(file);
                            break;
                    }
                    this.d = objOpen;
                    dVar.i(objOpen);
                    break;
                } catch (FileNotFoundException e3) {
                    Log.isLoggable("FileLoader", 3);
                    dVar.a(e3);
                }
        }
    }
}
