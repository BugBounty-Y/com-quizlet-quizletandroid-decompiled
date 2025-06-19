package androidx.navigation.internal;

import androidx.compose.foundation.lazy.grid.A;
import androidx.navigation.C1291m;
import androidx.navigation.compose.x;
import com.quizlet.eventlogger.features.deeplink.DeepLinkEventLog;
import com.quizlet.eventlogger.features.deeplink.DeepLinkEventLogger;
import com.quizlet.quizletandroid.ui.library.C4664i;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class f implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ f(int i, Object obj, Object obj2, Object obj3, Object obj4, boolean z) {
        this.a = i;
        this.c = obj;
        this.d = obj2;
        this.e = obj3;
        this.b = z;
        this.f = obj4;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        boolean z = this.b;
        int i = 21;
        Object obj2 = this.e;
        Object obj3 = this.d;
        Object obj4 = this.f;
        Object obj5 = this.c;
        switch (this.a) {
            case 0:
                C1291m entry = (C1291m) obj;
                Intrinsics.checkNotNullParameter(entry, "entry");
                ((F) obj5).a = true;
                ((F) obj3).a = true;
                ((j) obj2).p(entry, z, (C4927s) obj4);
                break;
            case 1:
                DeepLinkEventLog.Payload createEvent = (DeepLinkEventLog.Payload) obj;
                int i2 = DeepLinkEventLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setDeepLinkType((String) obj5);
                createEvent.setUri((String) obj3);
                createEvent.setReferrer((String) obj2);
                createEvent.setActivityTargets(((ArrayList) obj4).toString());
                createEvent.setEmailConfirmationRedirect(Boolean.valueOf(z));
                break;
            default:
                androidx.compose.foundation.lazy.grid.i LazyVerticalGrid = (androidx.compose.foundation.lazy.grid.i) obj;
                Intrinsics.checkNotNullParameter(LazyVerticalGrid, "$this$LazyVerticalGrid");
                x xVar = new x(i);
                kotlinx.collections.immutable.b bVar = (kotlinx.collections.immutable.b) obj5;
                LazyVerticalGrid.p(bVar.size(), new androidx.compose.ui.viewinterop.b(21, xVar, bVar), null, new com.quizlet.assembly.compose.menu.e(bVar, 13), new androidx.compose.runtime.internal.d(true, 1229287273, new C4664i(bVar, xVar, (A) obj3, (Function1) obj2, this.b, (Function1) obj4, 2)));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(String str, String str2, String str3, ArrayList arrayList, boolean z) {
        this.a = 1;
        this.c = str;
        this.d = str2;
        this.e = str3;
        this.f = arrayList;
        this.b = z;
    }
}
