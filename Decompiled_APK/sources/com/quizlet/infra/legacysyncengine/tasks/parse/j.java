package com.quizlet.infra.legacysyncengine.tasks.parse;

import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentityCollection;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.orm.RequestParameters;
import com.quizlet.infra.legacysyncengine.models.serializers.ApiThreeRequestSerializer;
import java.io.PipedOutputStream;
import java.util.List;
import okhttp3.A;

/* loaded from: classes3.dex */
public final class j extends g {
    public final ModelType d;
    public final com.quizlet.infra.legacysyncengine.net.constants.a e;
    public final List f;
    public final ApiThreeRequestSerializer g;

    public j(List list, com.quizlet.infra.legacysyncengine.net.constants.a aVar, PipedOutputStream pipedOutputStream, ApiThreeRequestSerializer apiThreeRequestSerializer, q qVar, A a) {
        super(a, qVar, pipedOutputStream);
        this.e = aVar;
        this.d = ((DBModel) list.get(0)).getModelType();
        this.f = list;
        this.g = apiThreeRequestSerializer;
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final String b() {
        return this.g.requestBodyForModels(this.f);
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final List c() {
        return this.g.requestFilesForModels(this.f);
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final String d() {
        String endpointRoot = this.d.getEndpointRoot();
        com.quizlet.infra.legacysyncengine.net.constants.a aVar = this.e;
        int iOrdinal = aVar.ordinal();
        if (iOrdinal == 2) {
            return android.support.v4.media.session.a.k(endpointRoot, "/save");
        }
        if (iOrdinal == 3) {
            String strUrlString = ModelIdentityCollection.identitiesForModels(this.f).urlString();
            return !org.apache.commons.lang3.e.c(strUrlString) ? android.support.v4.media.session.a.l(endpointRoot, "/", strUrlString) : endpointRoot;
        }
        throw new RuntimeException("Illegal request action: " + aVar);
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final String e() {
        StringBuilder sbX = android.support.v4.media.session.a.x("j", "_");
        sbX.append(this.e);
        sbX.append("_");
        sbX.append(this.d);
        return sbX.toString();
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final RequestParameters f() {
        return null;
    }

    @Override // com.quizlet.infra.legacysyncengine.tasks.parse.g
    public final com.quizlet.infra.legacysyncengine.net.constants.a g() {
        return this.e;
    }
}
