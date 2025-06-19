package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import android.content.Context;
import io.ktor.http.AbstractC4879a;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class i implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;

    public /* synthetic */ i(Function1 function1, boolean z) {
        this.a = 0;
        this.b = z;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.focus.s it2 = (androidx.compose.ui.focus.s) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (it2.a() && !this.b) {
                    ((Function1) this.c).invoke(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.m.a);
                }
                return Unit.a;
            case 1:
                Intrinsics.checkNotNullParameter((Context) obj, "it");
                com.quizlet.qatex.b bVar = new com.quizlet.qatex.b((Context) this.c, 0);
                bVar.setShouldDispatchTouchEvent(this.b);
                return bVar;
            default:
                Byte b = (Byte) obj;
                byte bByteValue = b.byteValue();
                boolean zContains = AbstractC4879a.a.contains(b);
                StringBuilder sb = (StringBuilder) this.c;
                if (zContains || AbstractC4879a.d.contains(b)) {
                    sb.append((char) bByteValue);
                } else if (this.b && bByteValue == 32) {
                    sb.append('+');
                } else {
                    sb.append(AbstractC4879a.g(bByteValue));
                }
                return Unit.a;
        }
    }

    public /* synthetic */ i(boolean z, int i, Object obj) {
        this.a = i;
        this.c = obj;
        this.b = z;
    }
}
