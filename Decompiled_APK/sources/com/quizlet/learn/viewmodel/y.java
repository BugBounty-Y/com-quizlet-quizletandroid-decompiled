package com.quizlet.learn.viewmodel;

import android.net.Uri;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.ads.Yh;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import com.quizlet.quizletandroid.managers.deeplinks.C4631e;
import com.quizlet.quizletandroid.util.links.NoMatchingQuizletClassFoundException;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Comparable c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ y(Object obj, Comparable comparable, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = comparable;
        this.d = obj2;
        this.e = obj3;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                Boolean isMeteringKillSwitchEnabled = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isMeteringKillSwitchEnabled, "isMeteringKillSwitchEnabled");
                G g = (G) this.b;
                kotlinx.coroutines.E.A(p0.j(g), g.A1, null, new x((com.quizlet.shared.enums.h) this.c, (Integer) this.d, (Integer) this.e, g, isMeteringKillSwitchEnabled, null), 2);
                break;
            case 1:
                Long classId = (Long) obj;
                Intrinsics.checkNotNullParameter(classId, "classId");
                Uri uri = (Uri) this.c;
                ((Yh) this.b).j(uri, (com.quizlet.quizletandroid.ui.deeplinkinterstitial.i) this.d, new C4631e(uri, classId, (String) this.e));
                break;
            default:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                com.quizlet.quizletandroid.ui.deeplinkinterstitial.i iVar = (com.quizlet.quizletandroid.ui.deeplinkinterstitial.i) this.d;
                Uri uri2 = (Uri) this.c;
                Yh yh = (Yh) this.b;
                yh.getClass();
                boolean z = error instanceof IOException;
                LoggedInUserStatus loggedInUserStatus = (LoggedInUserStatus) this.e;
                if (!z) {
                    if (!(error instanceof NoMatchingQuizletClassFoundException)) {
                        timber.log.c.a.e(error);
                        break;
                    } else {
                        timber.log.c.a.p(error);
                        yh.j(uri2, iVar, new com.quizlet.quizletandroid.managers.deeplinks.C(loggedInUserStatus.isLoggedIn() ? com.quizlet.quizletandroid.managers.deeplinks.B.a : com.quizlet.quizletandroid.managers.deeplinks.B.b));
                        break;
                    }
                } else {
                    yh.j(uri2, iVar, new com.quizlet.quizletandroid.managers.deeplinks.C(loggedInUserStatus.isLoggedIn() ? com.quizlet.quizletandroid.managers.deeplinks.B.a : com.quizlet.quizletandroid.managers.deeplinks.B.b));
                    break;
                }
        }
    }
}
