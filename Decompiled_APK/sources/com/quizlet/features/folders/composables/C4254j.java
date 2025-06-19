package com.quizlet.features.folders.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import com.quizlet.features.folders.data.C4294m;
import com.quizlet.features.practicetest.detail.data.C4405h;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.composables.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4254j implements kotlin.jvm.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C4254j(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        switch (this.a) {
            case 0:
                String title = (String) obj;
                long jLongValue = ((Long) obj3).longValue();
                long jLongValue2 = ((Long) obj4).longValue();
                Intrinsics.checkNotNullParameter(title, "title");
                Intrinsics.checkNotNullParameter((String) obj2, "<unused var>");
                ((com.quizlet.assembly.compose.modals.x) this.b).a();
                ((Function1) this.c).invoke(new C4294m(jLongValue, jLongValue2, title));
                break;
            case 1:
                String folderTitle = (String) obj;
                long jLongValue3 = ((Long) obj3).longValue();
                long jLongValue4 = ((Long) obj4).longValue();
                Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
                Intrinsics.checkNotNullParameter((String) obj2, "<unused var>");
                ((com.quizlet.features.infra.folder.menu.viewmodel.n) this.c).l(jLongValue3, jLongValue4, folderTitle);
                ((com.quizlet.assembly.compose.modals.x) this.b).a();
                break;
            default:
                int iIntValue = ((Integer) obj).intValue();
                boolean zBooleanValue = ((Boolean) obj2).booleanValue();
                boolean zBooleanValue2 = ((Boolean) obj3).booleanValue();
                Boolean bool = (Boolean) obj4;
                bool.getClass();
                ((InterfaceC0773a0) this.b).setValue(bool);
                ((Function1) this.c).invoke(new C4405h(iIntValue, zBooleanValue, zBooleanValue2));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C4254j(com.quizlet.assembly.compose.modals.x xVar, Function1 function1) {
        this.a = 0;
        this.b = xVar;
        this.c = function1;
    }
}
