package com.quizlet.infra.legacysyncengine.tasks.parse;

import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.db.data.orm.RequestParameters;
import java.io.PipedOutputStream;
import java.util.Collections;
import java.util.List;
import okhttp3.A;

/* loaded from: classes3.dex */
public final class i extends g {
    public final String d;
    public final RequestParameters e;

    public i(String str, RequestParameters requestParameters, PipedOutputStream pipedOutputStream, q qVar, A a) {
        super(a, qVar, pipedOutputStream);
        this.d = str;
        this.e = requestParameters;
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final String b() {
        return null;
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final List c() {
        return Collections.EMPTY_LIST;
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final String d() {
        return this.d;
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final String e() {
        StringBuilder sbX = android.support.v4.media.session.a.x("i", "_");
        sbX.append(this.d);
        sbX.append("_");
        sbX.append(com.quizlet.infra.legacysyncengine.net.constants.a.b);
        return sbX.toString();
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final RequestParameters f() {
        return this.e;
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final com.quizlet.infra.legacysyncengine.net.constants.a g() {
        return com.quizlet.infra.legacysyncengine.net.constants.a.b;
    }
}
