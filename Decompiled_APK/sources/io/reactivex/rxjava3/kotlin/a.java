package io.reactivex.rxjava3.kotlin;

import io.reactivex.rxjava3.functions.e;
import kotlin.Pair;
import kotlin.v;

/* loaded from: classes3.dex */
public final class a implements io.reactivex.rxjava3.functions.b, e {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public static final a d = new a(2);
    public static final a e = new a(3);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        switch (this.a) {
        }
        return new Pair(obj, obj2);
    }

    @Override // io.reactivex.rxjava3.functions.e
    public Object k(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
        }
        return new v(obj, obj2, obj3);
    }
}
