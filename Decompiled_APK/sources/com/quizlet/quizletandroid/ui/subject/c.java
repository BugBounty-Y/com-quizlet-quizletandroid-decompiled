package com.quizlet.quizletandroid.ui.subject;

import android.content.ComponentCallbacks2;
import androidx.activity.s;
import androidx.appcompat.app.AbstractActivityC0055k;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.navigationmanagers.i;
import com.quizlet.quizletandroid.ui.usersettings.activities.ChangeProfileImageActivity;
import com.quizlet.quizletandroid.ui.usersettings.activities.CropImageActivity;
import com.quizlet.quizletandroid.ui.webpages.WebViewActivity;
import com.quizlet.quizletandroid.util.g;
import com.quizlet.security.challenge.activity.SecurityChallengeActivity;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;

/* loaded from: classes3.dex */
public final class c implements androidx.activity.contextaware.b {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractActivityC0055k b;

    public /* synthetic */ c(AbstractActivityC0055k abstractActivityC0055k, int i) {
        this.a = i;
        this.b = abstractActivityC0055k;
    }

    @Override // androidx.activity.contextaware.b
    public final void a(s sVar) {
        AbstractActivityC0055k abstractActivityC0055k = this.b;
        switch (this.a) {
            case 0:
                SubjectCategoryActivity subjectCategoryActivity = (SubjectCategoryActivity) abstractActivityC0055k;
                if (!subjectCategoryActivity.h) {
                    subjectCategoryActivity.h = true;
                    subjectCategoryActivity.c = ((C4622e) ((e) subjectCategoryActivity.d())).b.Q0();
                    break;
                }
                break;
            case 1:
                ChangeProfileImageActivity changeProfileImageActivity = (ChangeProfileImageActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B = N6.b(changeProfileImageActivity.getApplicationContext());
                if (componentCallbacks2B instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u()) && !changeProfileImageActivity.n) {
                        changeProfileImageActivity.n = true;
                        C4622e c4622e = (C4622e) ((com.quizlet.quizletandroid.ui.usersettings.activities.a) changeProfileImageActivity.d());
                        changeProfileImageActivity.c = c4622e.a();
                        changeProfileImageActivity.e = c4622e.b.Q0();
                        break;
                    }
                }
                break;
            case 2:
                CropImageActivity cropImageActivity = (CropImageActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B2 = N6.b(cropImageActivity.getApplicationContext());
                if (componentCallbacks2B2 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B2 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B2).u()) && !cropImageActivity.n) {
                        cropImageActivity.n = true;
                        C4622e c4622e2 = (C4622e) ((com.quizlet.quizletandroid.ui.usersettings.activities.c) cropImageActivity.d());
                        cropImageActivity.c = c4622e2.a();
                        cropImageActivity.e = c4622e2.b.Q0();
                        break;
                    }
                }
                break;
            case 3:
                ((WebViewActivity) abstractActivityC0055k).a0();
                break;
            case 4:
                SecurityChallengeActivity securityChallengeActivity = (SecurityChallengeActivity) abstractActivityC0055k;
                if (!securityChallengeActivity.f) {
                    securityChallengeActivity.f = true;
                    ((com.quizlet.security.challenge.activity.e) securityChallengeActivity.d()).getClass();
                    break;
                }
                break;
            default:
                UpgradeActivity upgradeActivity = (UpgradeActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B3 = N6.b(upgradeActivity.getApplicationContext());
                if (componentCallbacks2B3 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B3 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B3).u()) && !upgradeActivity.p) {
                        upgradeActivity.p = true;
                        C4622e c4622e3 = (C4622e) ((com.quizlet.upgrade.ui.activity.e) upgradeActivity.d());
                        upgradeActivity.c = c4622e3.a();
                        u uVar = c4622e3.b;
                        upgradeActivity.e = uVar.Q0();
                        g gVar = (g) uVar.B1.get();
                        com.quizlet.quizletandroid.ui.webpages.a aVar = com.quizlet.quizletandroid.ui.webpages.a.a;
                        upgradeActivity.q = new i(gVar);
                        break;
                    }
                }
                break;
        }
    }
}
