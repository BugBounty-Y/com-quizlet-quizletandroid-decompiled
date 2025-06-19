package com.quizlet.infra.legacysyncengine.tasks.parse;

import android.net.Uri;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.google.firebase.perf.network.FirebasePerfOkHttpClient;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.db.data.orm.RequestParameters;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import okhttp3.A;
import okhttp3.C;
import okhttp3.s;

/* loaded from: classes3.dex */
public abstract class g implements Runnable {
    public final A a;
    public final q b;
    public final PipedOutputStream c;

    public g(A a, q qVar, PipedOutputStream pipedOutputStream) {
        this.a = a;
        this.b = qVar;
        this.c = pipedOutputStream;
    }

    public final C a() {
        String str;
        String strD = d();
        RequestParameters requestParametersF = f();
        com.quizlet.infra.legacysyncengine.net.constants.a aVarG = g();
        int iOrdinal = aVarG.ordinal();
        if (iOrdinal == 1) {
            str = "GET";
        } else if (iOrdinal == 2) {
            str = "POST";
        } else {
            if (iOrdinal != 3) {
                throw new RuntimeException("Illegal request action: " + aVarG);
            }
            str = "DELETE";
        }
        Uri.Builder builderAppendEncodedPath = Uri.parse(((s) this.b.b).k().toString()).buildUpon().appendEncodedPath(strD);
        if (requestParametersF != null) {
            for (androidx.core.util.c cVar : requestParametersF.getKeyValuePairs()) {
                builderAppendEncodedPath.appendQueryParameter((String) cVar.a, (String) cVar.b);
            }
        }
        String string = builderAppendEncodedPath.build().toString();
        HashMap map = new HashMap();
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = new com.quizlet.data.repository.studysetwithcreatorinclass.g(11);
        gVar.b = string;
        gVar.c = str;
        for (Map.Entry entry : map.entrySet()) {
            ((com.android.billingclient.api.h) gVar.d).a((String) entry.getKey(), (String) entry.getValue());
        }
        gVar.e = b();
        if (com.quizlet.infra.legacysyncengine.net.constants.a.c.equals(g())) {
            gVar.f = c();
        }
        return gVar.d();
    }

    public abstract String b();

    public abstract List c();

    public abstract String d();

    public abstract String e();

    public abstract RequestParameters f();

    public abstract com.quizlet.infra.legacysyncengine.net.constants.a g();

    @Override // java.lang.Runnable
    public final void run() throws IOException {
        PipedOutputStream pipedOutputStream = this.c;
        String strE = e();
        Thread.currentThread().setName(strE);
        InputStream inputStreamI0 = null;
        try {
            try {
                try {
                    try {
                        inputStreamI0 = FirebasePerfOkHttpClient.execute(this.a.c(a())).g.f0().i0();
                        byte[] bArr = new byte[32768];
                        while (true) {
                            int i = inputStreamI0.read(bArr, 0, 32768);
                            if (i == -1) {
                                break;
                            } else {
                                pipedOutputStream.write(bArr, 0, i);
                            }
                        }
                        inputStreamI0.close();
                        pipedOutputStream.close();
                    } catch (IOException e) {
                        timber.log.c.a(e);
                    }
                } catch (JsonGenerationException e2) {
                    timber.log.c.a.f(e2, "JSON GENERATION EXCEPTION: %s", strE);
                    if (inputStreamI0 != null) {
                        inputStreamI0.close();
                    }
                    pipedOutputStream.close();
                }
            } catch (JsonMappingException e3) {
                timber.log.c.a.f(e3, "JSON MAPPING EXCEPTION: %s", strE);
                if (inputStreamI0 != null) {
                    inputStreamI0.close();
                }
                pipedOutputStream.close();
            } catch (IOException unused) {
                timber.log.c.a.a("IO EXCEPTION: %s", strE);
                if (inputStreamI0 != null) {
                    inputStreamI0.close();
                }
                pipedOutputStream.close();
            }
            Thread.currentThread().setName("IdleRequestTask");
        } catch (Throwable th) {
            if (0 != 0) {
                try {
                    inputStreamI0.close();
                } catch (IOException e4) {
                    timber.log.c.a(e4);
                    throw th;
                }
            }
            pipedOutputStream.close();
            throw th;
        }
    }
}
