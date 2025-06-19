package com.quizlet.quizletandroid.ui.login.authmanagers;

import com.quizlet.braze.e;
import com.quizlet.data.repository.set.f;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.match.data.V;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g;
import io.ktor.client.plugins.api.d;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ a(boolean z, Object obj, Object obj2, int i) {
        this.a = i;
        this.b = z;
        this.c = obj;
        this.d = obj2;
    }

    @Override // io.reactivex.rxjava3.functions.a
    public final void run() {
        switch (this.a) {
            case 0:
                if (this.b && !((DBUser) this.c).getIsUnderAge()) {
                    f fVar = (f) ((d) this.d).d;
                    DBUser dBUser = ((com.quizlet.infra.legacysyncengine.managers.d) fVar.b).r;
                    if (dBUser != null) {
                        dBUser.setSrsPushNotificationsEnabled(true);
                        ((e) fVar.c).b(true);
                        ((com.quizlet.infra.legacysyncengine.net.f) fVar.d).a(dBUser);
                        break;
                    }
                }
                break;
            default:
                if (this.b) {
                    g gVar = (g) this.c;
                    if (gVar.m.d() instanceof V) {
                        gVar.C(((MatchSettingsData) this.d).a);
                        break;
                    }
                }
                break;
        }
    }
}
