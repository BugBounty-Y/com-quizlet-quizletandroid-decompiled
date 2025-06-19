package com.bumptech.glide.load.model;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.text.TextUtils;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.ByteBuffer;

/* loaded from: classes.dex */
public final class n implements com.bumptech.glide.load.data.e {
    public static final String[] d = {"_data"};
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ n(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    private final void a() {
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

    @Override // com.bumptech.glide.load.data.e
    public final void f() {
        int i = this.a;
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
                return File.class;
            default:
                return ((C1535c) this.c).b();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final void h(com.bumptech.glide.g gVar, com.bumptech.glide.load.data.d dVar) {
        Object objWrap;
        switch (this.a) {
            case 0:
                Cursor cursorQuery = ((Context) this.b).getContentResolver().query((Uri) this.c, d, null, null, null);
                if (cursorQuery != null) {
                    try {
                        string = cursorQuery.moveToFirst() ? cursorQuery.getString(cursorQuery.getColumnIndexOrThrow("_data")) : null;
                        cursorQuery.close();
                    } catch (Throwable th) {
                        cursorQuery.close();
                        throw th;
                    }
                }
                if (!TextUtils.isEmpty(string)) {
                    dVar.i(new File(string));
                    return;
                }
                dVar.a(new FileNotFoundException("Failed to find file path for: " + ((Uri) this.c)));
                return;
            default:
                C1535c c1535c = (C1535c) this.c;
                byte[] bArr = (byte[]) this.b;
                switch (c1535c.a) {
                    case 0:
                        objWrap = ByteBuffer.wrap(bArr);
                        break;
                    default:
                        objWrap = new ByteArrayInputStream(bArr);
                        break;
                }
                dVar.i(objWrap);
                return;
        }
    }
}
