package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import android.app.Application;
import androidx.lifecycle.C0;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import com.quizlet.search.NewSearchFragment;
import com.quizlet.search.TermSearchFragment;
import com.quizlet.upgrade.ui.fragment.UpgradePlansModalFragment;
import com.quizlet.upgrade.upsell.ui.UpsellModalFragment;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import leakcanary.y;
import org.wordpress.aztec.spans.AztecStyleCiteSpan;
import org.wordpress.aztec.spans.AztecStyleEmphasisSpan;
import org.wordpress.aztec.spans.AztecStyleStrongSpan;

/* loaded from: classes3.dex */
public final class t extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ t(Object obj, int i) {
        super(0);
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return (StandardMatchGameFragment) this.b;
            case 1:
                return (C0) ((t) this.b).invoke();
            case 2:
                return (C0) ((com.quizlet.quizletandroid.ui.studymodes.testmode.start.n) this.b).invoke();
            case 3:
                return (ChangeProfileImageFragment) this.b;
            case 4:
                return (C0) ((t) this.b).invoke();
            case 5:
                return (NewSearchFragment) this.b;
            case 6:
                return (C0) ((t) this.b).invoke();
            case 7:
                return (TermSearchFragment) this.b;
            case 8:
                return (C0) ((t) this.b).invoke();
            case 9:
                return ((com.quizlet.shared.persistence.db.persistencedatabase.c) this.b).c;
            case 10:
                return (C0) ((com.quizlet.upgrade.ui.fragment.h) this.b).invoke();
            case 11:
                return (C0) ((com.quizlet.upgrade.ui.fragment.h) this.b).invoke();
            case 12:
                return (UpgradePlansModalFragment) this.b;
            case 13:
                return (C0) ((t) this.b).invoke();
            case 14:
                return (UpsellModalFragment) this.b;
            case 15:
                return (C0) ((t) this.b).invoke();
            case 16:
                y.a((Application) ((leakcanary.g) this.b).c);
                return Unit.a;
            case 17:
                okhttp3.q qVar = ((okhttp3.internal.connection.i) this.b).e;
                Intrinsics.d(qVar);
                List<Certificate> listA = qVar.a();
                ArrayList arrayList = new ArrayList(C.q(listA, 10));
                for (Certificate certificate : listA) {
                    Intrinsics.e(certificate, "null cannot be cast to non-null type java.security.cert.X509Certificate");
                    arrayList.add((X509Certificate) certificate);
                }
                return arrayList;
            case 18:
                return "| >> parameters " + ((org.koin.core.parameter.a) this.b) + ' ';
            case 19:
                if (((AztecStyleCiteSpan) this.b).getStyle() == 2) {
                    return "cite";
                }
                throw new IllegalArgumentException();
            case 20:
                if (((AztecStyleEmphasisSpan) this.b).getStyle() == 2) {
                    return "em";
                }
                throw new IllegalArgumentException();
            default:
                if (((AztecStyleStrongSpan) this.b).getStyle() == 1) {
                    return "strong";
                }
                throw new IllegalArgumentException();
        }
    }
}
