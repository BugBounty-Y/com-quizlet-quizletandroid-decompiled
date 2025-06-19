package com.jakewharton.rxbinding4;

import android.view.View;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.ads.C2245jv;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E;
import com.jakewharton.rxbinding4.widget.c;
import io.reactivex.rxjava3.core.g;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.j;
import io.reactivex.rxjava3.core.k;
import io.reactivex.rxjava3.core.l;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.exceptions.CompositeException;
import io.reactivex.rxjava3.internal.disposables.b;
import io.reactivex.rxjava3.internal.operators.maybe.v;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import io.reactivex.rxjava3.internal.operators.observable.Q;
import io.reactivex.rxjava3.internal.operators.observable.S;
import java.util.Iterator;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.InterfaceC5179d;
import retrofit2.u;

/* loaded from: classes2.dex */
public final class a extends i {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(l observer) {
        int i = 1;
        int i2 = 0;
        switch (this.a) {
            case 0:
                Intrinsics.f(observer, "observer");
                ((c) this.b).z(observer);
                return;
            case 1:
                Intrinsics.f(observer, "observer");
                if (E.b(observer)) {
                    View view = (View) this.b;
                    com.jakewharton.rxbinding4.view.a aVar = new com.jakewharton.rxbinding4.view.a(view, observer);
                    observer.a(aVar);
                    view.setOnClickListener(aVar);
                    return;
                }
                return;
            case 2:
                ((g) this.b).e(new v(observer, i2));
                return;
            case 3:
                C4899s c4899s = new C4899s(observer);
                observer.a(c4899s);
                try {
                    ((j) this.b).l(c4899s);
                    return;
                } catch (Throwable th) {
                    x7.b(th);
                    if (c4899s.e(th)) {
                        return;
                    }
                    C7.c(th);
                    return;
                }
            case 4:
                try {
                    Object obj = ((io.reactivex.rxjava3.functions.j) this.b).get();
                    Objects.requireNonNull(obj, "The supplier returned a null ObservableSource");
                    ((k) obj).c(observer);
                    return;
                } catch (Throwable th2) {
                    x7.b(th2);
                    b.d(th2, observer);
                    return;
                }
            case 5:
                try {
                    th = ((io.reactivex.rxjava3.internal.functions.c) this.b).a;
                } catch (Throwable th3) {
                    th = th3;
                    x7.b(th);
                }
                if (th == null) {
                    throw io.reactivex.rxjava3.internal.util.c.a("Supplier returned a null Throwable.");
                }
                C2245jv c2245jv = io.reactivex.rxjava3.internal.util.c.a;
                b.d(th, observer);
                return;
            case 6:
                Object[] objArr = (Object[]) this.b;
                Q q = new Q(observer, objArr);
                observer.a(q);
                if (q.d) {
                    return;
                }
                int length = objArr.length;
                while (i2 < length && !q.e) {
                    Object obj2 = objArr[i2];
                    if (obj2 == null) {
                        q.a.onError(new NullPointerException(AbstractC0147y.c(i2, "The element at index ", " is null")));
                        return;
                    } else {
                        q.a.b(obj2);
                        i2++;
                    }
                }
                if (q.e) {
                    return;
                }
                q.a.onComplete();
                return;
            case 7:
                try {
                    Iterator it2 = ((Iterable) this.b).iterator();
                    try {
                        if (!it2.hasNext()) {
                            b.a(observer);
                            return;
                        }
                        S s = new S(observer, it2);
                        observer.a(s);
                        if (s.d) {
                            return;
                        }
                        while (!s.c) {
                            try {
                                Object next = s.b.next();
                                Objects.requireNonNull(next, "The iterator returned a null value");
                                s.a.b(next);
                                if (s.c) {
                                    return;
                                }
                                try {
                                    if (!s.b.hasNext()) {
                                        if (s.c) {
                                            return;
                                        }
                                        s.a.onComplete();
                                        return;
                                    }
                                } catch (Throwable th4) {
                                    x7.b(th4);
                                    s.a.onError(th4);
                                    return;
                                }
                            } catch (Throwable th5) {
                                x7.b(th5);
                                s.a.onError(th5);
                                return;
                            }
                        }
                        return;
                    } catch (Throwable th6) {
                        x7.b(th6);
                        b.d(th6, observer);
                        return;
                    }
                } catch (Throwable th7) {
                    x7.b(th7);
                    b.d(th7, observer);
                    return;
                }
            case 8:
                ((p) this.b).j(new v(observer, i));
                return;
            default:
                InterfaceC5179d interfaceC5179dMo151clone = ((u) this.b).clone();
                retrofit2.adapter.rxjava3.c cVar = new retrofit2.adapter.rxjava3.c(interfaceC5179dMo151clone);
                observer.a(cVar);
                if (cVar.b) {
                    return;
                }
                try {
                    Object objA = ((u) interfaceC5179dMo151clone).a();
                    if (!cVar.b) {
                        observer.b(objA);
                    }
                    if (cVar.b) {
                        return;
                    }
                    try {
                        observer.onComplete();
                        return;
                    } catch (Throwable th8) {
                        th = th8;
                        x7.b(th);
                        if (i != 0) {
                            C7.c(th);
                            return;
                        }
                        if (cVar.b) {
                            return;
                        }
                        try {
                            observer.onError(th);
                            return;
                        } catch (Throwable th9) {
                            x7.b(th9);
                            C7.c(new CompositeException(th, th9));
                            return;
                        }
                    }
                } catch (Throwable th10) {
                    th = th10;
                    i = 0;
                }
        }
    }

    public a(View view) {
        this.a = 1;
        Intrinsics.f(view, "view");
        this.b = view;
    }
}
