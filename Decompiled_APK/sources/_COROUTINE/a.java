package _COROUTINE;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.internal.e;
import androidx.glance.appwidget.action.g;
import androidx.glance.n;
import androidx.glance.p;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3180j7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3207m7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3243q7;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3320b;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.quizlet.data.model.B2;
import com.quizlet.data.model.C2;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.z;
import com.quizlet.quizletandroid.ui.widgets.D;
import com.quizlet.quizletandroid.ui.widgets.E;
import com.quizlet.quizletandroid.ui.widgets.t;
import com.quizlet.themes.m;
import com.quizlet.ui.resources.designsystem.generated.f;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.collections.immutable.b;
import okhttp3.internal.platform.d;

/* loaded from: classes.dex */
public abstract class a {
    public static final /* synthetic */ int a = 0;

    public static final void a(C2 c2, androidx.appcompat.view.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-214378187);
        if ((((c0814p.h(c2) ? 4 : 2) | i | (c0814p.f(aVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i2 = d.b(c2) ? R.drawable.bg_shape_fire_half_hcut_on : R.drawable.bg_shape_fire_half_hcut_off;
            p pVarD = AbstractC3332e.d(n.a);
            m mVar = m.g;
            mVar.c();
            p pVarF = AbstractC3332e.f(AbstractC3180j7.b(AbstractC3243q7.e(pVarD, f.h), new androidx.glance.a(R.drawable.bg_widget_large_current_streak)), 96);
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            float f = 12;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            AbstractC3320b.a(AbstractC3207m7.b(AbstractC3324c.f(pVarF, f, f, f, DefinitionKt.NO_Float_VALUE, 8), g.a(aVar.b())), 0, e.e(115018623, new com.quizlet.features.notes.modals.e(i2, c2, 2), c0814p), c0814p, 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p(c2, aVar, i, 3);
        }
    }

    public static final void b(B2 b2, androidx.appcompat.view.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-713589080);
        if ((((c0814p.h(b2) ? 4 : 2) | i | (c0814p.f(aVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i2 = b2.d;
            int i3 = b2.e;
            int i4 = i2 + i3;
            int i5 = b2.f;
            int i6 = i4 + i5;
            Intrinsics.checkNotNullParameter(b2, "<this>");
            int i7 = b2.d + i3;
            int i8 = ((float) i7) / ((float) (i7 + i5)) == 1.0f ? R.drawable.bg_widget_large_trophy_filled : R.drawable.bg_widget_large_trophy_empty;
            p pVarD = AbstractC3332e.d(n.a);
            m mVar = m.g;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            mVar.u();
            float f = j.g;
            mVar.u();
            p pVarB = AbstractC3207m7.b(AbstractC3324c.f(pVarD, f, 12, f, DefinitionKt.NO_Float_VALUE, 8), g.a(aVar.c(b2.a)));
            c0814p.X(1000046074);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new z(27);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3320b.a(AbstractC3340g.c(pVarB, (Function1) objI), 0, e.e(-344358754, new D(b2, i6, i4, i8), c0814p), c0814p, 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.studymodes.testmode.start.p(b2, aVar, i, 4);
        }
    }

    public static final void c(int i, B2 b2, androidx.appcompat.view.a aVar, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        float f;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1014093649);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.h(b2) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= (i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p.f(aVar) : c0814p.h(aVar) ? 256 : 128;
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (i == 0) {
                Intrinsics.checkNotNullParameter(m.g, "<this>");
                f = 12;
            } else {
                m.g.u();
                f = j.g;
            }
            float f2 = f;
            n nVar = n.a;
            m mVar = m.g;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            float f3 = 12;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            p pVarF = AbstractC3324c.f(nVar, f3, f2, f3, DefinitionKt.NO_Float_VALUE, 8);
            c0814p.X(-838247248);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new z(26);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            M7.a(AbstractC3340g.c(pVarF, (Function1) objI), null, e.e(1645861009, new t(aVar, b2, 1), c0814p), c0814p, 384, 2);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.n(i, b2, aVar, i2);
        }
    }

    public static final void d(C2 streakData, b sets, androidx.appcompat.view.a linkProvider, p pVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        p pVar2;
        Intrinsics.checkNotNullParameter(streakData, "streakData");
        Intrinsics.checkNotNullParameter(sets, "sets");
        Intrinsics.checkNotNullParameter(linkProvider, "linkProvider");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-396633912);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(streakData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(sets) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p.f(linkProvider) : c0814p.h(linkProvider) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            pVar2 = pVar;
        } else {
            n nVar = n.a;
            B2 b2 = (B2) CollectionsKt.L(sets);
            boolean z = true;
            List listH = CollectionsKt.H(1, sets);
            p pVarB = AbstractC3180j7.b(nVar, new androidx.glance.a(R.drawable.bg_widget_large_recent_sets));
            c0814p.X(-1861341616);
            boolean zH = c0814p.h(streakData) | c0814p.h(b2);
            if ((i3 & 896) != 256 && ((i3 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 || !c0814p.h(linkProvider))) {
                z = false;
            }
            boolean zH2 = zH | z | c0814p.h(listH);
            Object objI = c0814p.I();
            if (zH2 || objI == C0804k.a) {
                androidx.navigation.internal.e eVar = new androidx.navigation.internal.e(listH, streakData, b2, linkProvider, 9);
                c0814p.i0(eVar);
                objI = eVar;
            }
            c0814p.p(false);
            z7.b(pVarB, (Function1) objI, c0814p, 0);
            pVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(streakData, sets, linkProvider, pVar2, i, 7);
        }
    }

    public static final void e(C2 c2, B2 b2, androidx.appcompat.view.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-50241241);
        if ((((c0814p.h(c2) ? 4 : 2) | i | (c0814p.h(b2) ? 32 : 16) | (c0814p.f(aVar) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            p pVarB = AbstractC3180j7.b(AbstractC3332e.f(n.a, Math.max(Math.min(260, androidx.compose.ui.unit.g.a(((androidx.compose.ui.unit.g) c0814p.j(androidx.glance.j.a)).a)), 220)), new androidx.glance.a(R.drawable.bg_widget_large_top_card));
            m mVar = m.g;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            float f = 12;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            AbstractC3320b.a(AbstractC3324c.f(pVarB, f, f, f, DefinitionKt.NO_Float_VALUE, 8), 0, e.e(-1327486735, new E(c2, aVar, b2), c0814p), c0814p, 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 12, c2, b2, aVar);
        }
    }

    public static Object f(Parcel parcel, Parcelable.Creator creator) {
        if (parcel.readInt() != 0) {
            return creator.createFromParcel(parcel);
        }
        return null;
    }
}
