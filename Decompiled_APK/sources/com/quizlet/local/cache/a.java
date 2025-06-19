package com.quizlet.local.cache;

import androidx.collection.C0220s;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class a implements com.quizlet.cache.a {
    public final /* synthetic */ int a;
    public final Object b;

    public a(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new C0220s(16);
                break;
            default:
                this.b = new LinkedHashMap();
                break;
        }
    }

    @Override // com.quizlet.cache.a
    public final void a(Object key, Object obj) {
        switch (this.a) {
            case 0:
                ((LinkedHashMap) this.b).put(key, obj);
                break;
            default:
                Intrinsics.checkNotNullParameter(key, "key");
                C0220s c0220s = (C0220s) this.b;
                if (obj != null) {
                    c0220s.k(key, obj);
                    break;
                } else {
                    c0220s.l(key);
                    break;
                }
        }
    }

    @Override // com.quizlet.cache.a
    public final void b(Object key) {
        switch (this.a) {
            case 0:
                ((LinkedHashMap) this.b).remove(key);
                break;
            default:
                Intrinsics.checkNotNullParameter(key, "key");
                ((C0220s) this.b).l(key);
                break;
        }
    }

    @Override // com.quizlet.cache.a
    public final Object get(Object key) {
        switch (this.a) {
            case 0:
                return ((LinkedHashMap) this.b).get(key);
            default:
                Intrinsics.checkNotNullParameter(key, "key");
                return ((C0220s) this.b).g(key);
        }
    }
}
