package androidx.compose.foundation.interaction;

import androidx.compose.runtime.InterfaceC0773a0;
import java.util.ArrayList;
import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class f implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ ArrayList b;
    public final /* synthetic */ InterfaceC0773a0 c;

    public /* synthetic */ f(ArrayList arrayList, InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = arrayList;
        this.c = interfaceC0773a0;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                j jVar = (j) obj;
                boolean z = jVar instanceof d;
                ArrayList arrayList = this.b;
                if (z) {
                    arrayList.add(jVar);
                } else if (jVar instanceof e) {
                    arrayList.remove(((e) jVar).a);
                }
                this.c.setValue(Boolean.valueOf(!arrayList.isEmpty()));
                break;
            default:
                j jVar2 = (j) obj;
                boolean z2 = jVar2 instanceof o;
                ArrayList arrayList2 = this.b;
                if (z2) {
                    arrayList2.add(jVar2);
                } else if (jVar2 instanceof p) {
                    arrayList2.remove(((p) jVar2).a);
                } else if (jVar2 instanceof n) {
                    arrayList2.remove(((n) jVar2).a);
                }
                this.c.setValue(Boolean.valueOf(!arrayList2.isEmpty()));
                break;
        }
        return Unit.a;
    }
}
