package com.bumptech.glide.load.data;

import android.content.ContentResolver;
import android.content.res.AssetManager;
import android.net.Uri;
import android.util.Log;
import java.io.FileNotFoundException;
import java.io.IOException;

/* loaded from: classes.dex */
public abstract class b implements e {
    public final /* synthetic */ int a;
    public Object b;
    public final Comparable c;
    public final Object d;

    public /* synthetic */ b(int i, Comparable comparable, Object obj) {
        this.a = i;
        this.d = obj;
        this.c = comparable;
    }

    private final void a() {
    }

    private final void b() {
    }

    public abstract void c(Object obj);

    @Override // com.bumptech.glide.load.data.e
    public final void cancel() {
        int i = this.a;
    }

    public abstract Object d(ContentResolver contentResolver, Uri uri);

    public abstract Object e(AssetManager assetManager, String str);

    @Override // com.bumptech.glide.load.data.e
    public final void f() {
        switch (this.a) {
            case 0:
                Object obj = this.b;
                if (obj != null) {
                    try {
                        c(obj);
                        break;
                    } catch (IOException unused) {
                        return;
                    }
                }
                break;
            default:
                Object obj2 = this.b;
                if (obj2 != null) {
                    try {
                        c(obj2);
                        break;
                    } catch (IOException unused2) {
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
    public final void h(com.bumptech.glide.g gVar, d dVar) {
        switch (this.a) {
            case 0:
                try {
                    Object objE = e((AssetManager) this.d, (String) this.c);
                    this.b = objE;
                    dVar.i(objE);
                    break;
                } catch (IOException e) {
                    Log.isLoggable("AssetPathFetcher", 3);
                    dVar.a(e);
                }
            default:
                try {
                    Object objD = d((ContentResolver) this.d, (Uri) this.c);
                    this.b = objD;
                    dVar.i(objD);
                    break;
                } catch (FileNotFoundException e2) {
                    Log.isLoggable("LocalUriFetcher", 3);
                    dVar.a(e2);
                    return;
                }
        }
    }
}
