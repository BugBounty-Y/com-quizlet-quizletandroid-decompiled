package androidx.navigation.compose;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.navigation.C1291m;
import com.comscore.streaming.EventType;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class z implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0773a0 b;

    public /* synthetic */ z(InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                List list = (List) this.b.getValue();
                ArrayList arrayList = new ArrayList();
                for (Object obj : list) {
                    if (Intrinsics.b(((C1291m) obj).b.a, "composable")) {
                        arrayList.add(obj);
                    }
                }
                break;
            case 1:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 2:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 3:
                this.b.setValue(Boolean.FALSE);
                break;
            case 4:
                this.b.setValue(Boolean.TRUE);
                break;
            case 5:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 6:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 7:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 8:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 9:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 10:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 11:
                this.b.setValue(Boolean.FALSE);
                break;
            case 12:
                this.b.setValue(Boolean.TRUE);
                break;
            case 13:
                this.b.setValue(Boolean.FALSE);
                break;
            case 14:
                this.b.setValue(Boolean.TRUE);
                break;
            case 15:
                this.b.setValue(Boolean.FALSE);
                break;
            case 16:
                this.b.setValue(Boolean.FALSE);
                break;
            case 17:
                this.b.setValue(Boolean.FALSE);
                break;
            case 18:
                this.b.setValue(Boolean.FALSE);
                break;
            case 19:
                this.b.setValue(Boolean.FALSE);
                break;
            case 20:
                this.b.setValue(Boolean.TRUE);
                break;
            case 21:
                this.b.setValue(Boolean.FALSE);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                this.b.setValue(Boolean.TRUE);
                break;
            case EventType.AUDIO /* 23 */:
                this.b.setValue(Boolean.FALSE);
                break;
            case EventType.VIDEO /* 24 */:
                this.b.setValue(Boolean.FALSE);
                break;
            case EventType.SUBS /* 25 */:
                this.b.setValue(Boolean.FALSE);
                break;
            case EventType.CDN /* 26 */:
                this.b.setValue(Boolean.FALSE);
                break;
            case 27:
                this.b.setValue(Boolean.FALSE);
                break;
            case 28:
                this.b.setValue(Boolean.FALSE);
                break;
            default:
                this.b.setValue(Boolean.FALSE);
                break;
        }
        return Unit.a;
    }
}
