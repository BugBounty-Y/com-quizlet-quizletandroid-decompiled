package com.quizlet.db.data.models.persisted.types;

import com.quizlet.edgy.ui.fragment.EdgyAddSchoolAndCoursesFragment;
import com.quizlet.explanations.textbook.tableofcontents.ui.TableOfContentsFragment;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {
        switch (this.a) {
            case 13:
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                break;
            case 16:
                String str = EdgyAddSchoolAndCoursesFragment.u;
                break;
            case 20:
                String str2 = TableOfContentsFragment.p;
                break;
        }
        return Unit.a;
    }
}
