package com.quizlet.quizletandroid.ui.startpage.nav2;

import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4721q;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4730u implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Y b;

    public /* synthetic */ C4730u(Y y, int i) {
        this.a = i;
        this.b = y;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        boolean z;
        List data = (List) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(data, "privacyPolicyData");
                Y y = this.b;
                C4721q c4721q = y.t;
                c4721q.getClass();
                Intrinsics.checkNotNullParameter(data, "data");
                c4721q.k = data;
                y.o1.j(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.j(data));
                return Unit.a;
            case 1:
                Intrinsics.checkNotNullParameter(data, "sources");
                this.b.getClass();
                if (data == null || !data.isEmpty()) {
                    Iterator it2 = data.iterator();
                    while (it2.hasNext()) {
                        if (((Boolean) it2.next()).booleanValue()) {
                            z = true;
                        }
                    }
                    z = false;
                } else {
                    z = false;
                }
                return Boolean.valueOf(z);
            default:
                Intrinsics.d(data);
                boolean zIsEmpty = data.isEmpty();
                Y y2 = this.b;
                if (!zIsEmpty) {
                    C4721q c4721q2 = y2.t;
                    c4721q2.getClass();
                    Intrinsics.checkNotNullParameter(data, "data");
                    c4721q2.a = data;
                }
                y2.d1.j(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.k(data));
                y2.C.j(Boolean.FALSE);
                return Unit.a;
        }
    }
}
