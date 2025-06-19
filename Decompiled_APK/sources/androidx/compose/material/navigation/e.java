package androidx.compose.material.navigation;

import androidx.compose.runtime.C0807l0;
import androidx.navigation.C1291m;
import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class e implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0807l0 b;

    public /* synthetic */ e(C0807l0 c0807l0, int i) {
        this.a = i;
        this.b = c0807l0;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                this.b.setValue((C1291m) obj);
                break;
            case 1:
                this.b.setValue(obj);
                break;
            case 2:
                this.b.setValue(obj);
                break;
            case 3:
                this.b.setValue(obj);
                break;
            default:
                this.b.setValue(obj);
                break;
        }
        return Unit.a;
    }
}
