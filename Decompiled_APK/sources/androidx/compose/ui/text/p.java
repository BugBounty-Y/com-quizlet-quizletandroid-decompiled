package androidx.compose.ui.text;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class p extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.remote.model.notes.e b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ p(com.quizlet.remote.model.notes.e eVar, int i) {
        super(0);
        this.a = i;
        this.b = eVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        Object obj;
        Object obj2;
        switch (this.a) {
            case 0:
                ArrayList arrayList = (ArrayList) this.b.f;
                if (arrayList.isEmpty()) {
                    obj = null;
                } else {
                    Object obj3 = arrayList.get(0);
                    float fB = ((r) obj3).a.i.b();
                    int i = kotlin.collections.B.i(arrayList);
                    int i2 = 1;
                    if (1 <= i) {
                        while (true) {
                            Object obj4 = arrayList.get(i2);
                            float fB2 = ((r) obj4).a.i.b();
                            if (Float.compare(fB, fB2) < 0) {
                                obj3 = obj4;
                                fB = fB2;
                            }
                            if (i2 != i) {
                                i2++;
                            }
                        }
                    }
                    obj = obj3;
                }
                r rVar = (r) obj;
                return Float.valueOf(rVar != null ? rVar.a.i.b() : DefinitionKt.NO_Float_VALUE);
            default:
                ArrayList arrayList2 = (ArrayList) this.b.f;
                if (arrayList2.isEmpty()) {
                    obj2 = null;
                } else {
                    Object obj5 = arrayList2.get(0);
                    float fB3 = ((r) obj5).a.b();
                    int i3 = kotlin.collections.B.i(arrayList2);
                    int i4 = 1;
                    if (1 <= i3) {
                        while (true) {
                            Object obj6 = arrayList2.get(i4);
                            float fB4 = ((r) obj6).a.b();
                            if (Float.compare(fB3, fB4) < 0) {
                                obj5 = obj6;
                                fB3 = fB4;
                            }
                            if (i4 != i3) {
                                i4++;
                            }
                        }
                    }
                    obj2 = obj5;
                }
                r rVar2 = (r) obj2;
                return Float.valueOf(rVar2 != null ? rVar2.a.b() : DefinitionKt.NO_Float_VALUE);
        }
    }
}
