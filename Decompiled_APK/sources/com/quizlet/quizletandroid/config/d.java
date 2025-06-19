package com.quizlet.quizletandroid.config;

import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements h {
    public final List a;

    public d(List strings, int i) {
        switch (i) {
            case 1:
                this.a = strings;
                break;
            default:
                Intrinsics.checkNotNullParameter(strings, "strings");
                this.a = strings;
                break;
        }
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List list = (List) obj;
        Intrinsics.checkNotNullParameter(list, "list");
        ArrayList arrayList = new ArrayList(list);
        arrayList.addAll(this.a);
        return arrayList;
    }
}
