package com.quizlet.quizletandroid.ui.startpage.nav2.composables;

import android.util.TypedValue;
import androidx.compose.runtime.B;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.X0;
import com.comscore.streaming.EventType;
import com.quizlet.data.model.C4125f;
import com.quizlet.data.model.C4137j;
import com.quizlet.data.model.C4149n;
import com.quizlet.data.model.g2;
import com.quizlet.data.model.r;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.themes.j;
import com.skydoves.balloon.Balloon;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import okhttp3.A;
import okhttp3.z;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Unit.a;
            case 1:
                return C0776c.z(Boolean.FALSE);
            case 2:
                return new com.quizlet.quizletandroid.ui.widgets.ui.theme.b(new com.quizlet.themes.b(false, 2), new com.quizlet.themes.b(true, 2));
            case 3:
                B b = com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a;
                return com.quizlet.quizletandroid.ui.widgets.ui.theme.d.a;
            case 4:
                return C4125f.a;
            case 5:
                return C4137j.a;
            case 6:
                return r.a;
            case 7:
                return g2.a;
            case 8:
                return C4149n.a;
            case 9:
                return Unit.a;
            case 10:
                return C0776c.z(Boolean.FALSE);
            case 11:
                return Unit.a;
            case 12:
                return Unit.a;
            case 13:
                return C0776c.z(null);
            case 14:
                return Integer.valueOf(SearchType.getEntries().size());
            case 15:
                return C0776c.z(Boolean.TRUE);
            case 16:
                return new com.quizlet.themes.d(null, null, null, 511);
            case 17:
                return new com.quizlet.themes.b(false, 3);
            case 18:
                return new j();
            case 19:
                return new com.quizlet.themes.c();
            case 20:
                X0 x0 = com.quizlet.themes.r.a;
                return 0;
            case 21:
                return new com.quizlet.themes.f();
            case EventType.WINDOW_STATE /* 22 */:
                return new TypedValue();
            case EventType.AUDIO /* 23 */:
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                return new com.quizlet.uicommon.ui.common.text.d();
            case EventType.SUBS /* 25 */:
                return Balloon.handler_delegate$lambda$0();
            case EventType.CDN /* 26 */:
                return Balloon.channel_delegate$lambda$56();
            case 27:
                return Balloon.scope_delegate$lambda$57();
            case 28:
                return new io.ktor.util.e();
            default:
                return new A(new z());
        }
    }
}
