package com.quizlet.search.composables;

import com.quizlet.data.model.C4186z1;
import com.quizlet.generated.enums.EnumC4484g1;
import com.quizlet.generated.enums.EnumC4490i1;
import com.quizlet.generated.enums.Y0;
import com.quizlet.search.data.SearchFilterContentTypeState;
import com.quizlet.search.data.SearchFilterCreatorTypeState;
import com.quizlet.search.data.SearchFilterNumTermsState;
import com.quizlet.search.data.SearchFiltersStates;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class F implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.search.viewmodels.A b;
    public final /* synthetic */ String c;

    public /* synthetic */ F(com.quizlet.search.viewmodels.A a, String str, int i) {
        this.a = i;
        this.b = a;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.C(this.c);
            default:
                com.quizlet.search.viewmodels.A a = this.b;
                com.quizlet.data.interactor.studysetwithcreator.a aVar = a.h;
                SearchFiltersStates searchFiltersStates = (SearchFiltersStates) a.n.getValue();
                SearchFilterNumTermsState searchFilterNumTermsState = searchFiltersStates.a;
                Object objA = searchFilterNumTermsState.a();
                if (objA == null) {
                    objA = searchFilterNumTermsState.a;
                }
                EnumC4484g1 enumC4484g1 = (EnumC4484g1) objA;
                SearchFilterCreatorTypeState searchFilterCreatorTypeState = searchFiltersStates.b;
                Object objA2 = searchFilterCreatorTypeState.a();
                if (objA2 == null) {
                    objA2 = searchFilterCreatorTypeState.a;
                }
                Y0 y0 = (Y0) objA2;
                SearchFilterContentTypeState searchFilterContentTypeState = searchFiltersStates.c;
                Object objA3 = searchFilterContentTypeState.a();
                if (objA3 == null) {
                    objA3 = searchFilterContentTypeState.a;
                }
                com.quizlet.search.paging.d dVar = new com.quizlet.search.paging.d(aVar, this.c, new C4186z1(enumC4484g1, y0, (EnumC4490i1) objA3), a.i, a);
                a.l = dVar;
                return dVar;
        }
    }
}
