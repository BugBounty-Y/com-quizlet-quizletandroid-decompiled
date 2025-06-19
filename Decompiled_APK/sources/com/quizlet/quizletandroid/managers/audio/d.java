package com.quizlet.quizletandroid.managers.audio;

import java.io.File;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements io.reactivex.rxjava3.functions.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.quizletandroid.data.cache.a b;
    public final /* synthetic */ String c;
    public final /* synthetic */ File d;

    public /* synthetic */ d(com.quizlet.quizletandroid.data.cache.a aVar, String str, File file, int i) {
        this.a = i;
        this.b = aVar;
        this.c = str;
        this.d = file;
    }

    @Override // io.reactivex.rxjava3.functions.a
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.c(this.d, this.c);
                break;
            default:
                this.b.c(this.d, this.c);
                break;
        }
    }
}
