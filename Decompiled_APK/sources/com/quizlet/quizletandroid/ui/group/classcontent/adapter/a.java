package com.quizlet.quizletandroid.ui.group.classcontent.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.V;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.infra.legacyadapter.viewholder.k;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.core.p;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends V {
    public final /* synthetic */ int c = 0;
    public final Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a clickListener) {
        super(new s(4));
        Intrinsics.checkNotNullParameter(clickListener, "clickListener");
        this.d = clickListener;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        switch (this.c) {
            case 0:
                com.quizlet.quizletandroid.ui.group.classcontent.models.a aVar = (com.quizlet.quizletandroid.ui.group.classcontent.models.a) d(i);
                if (aVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.models.d) {
                    return 0;
                }
                if (aVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.models.c) {
                    return 1;
                }
                if (aVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.models.e) {
                    return 2;
                }
                throw new NoWhenBranchMatchedException();
            default:
                if (i == 0) {
                    com.quizlet.quizletandroid.util.kext.a[] aVarArr = com.quizlet.quizletandroid.util.kext.a.a;
                    return 0;
                }
                if (i == getItemCount() - 1) {
                    com.quizlet.quizletandroid.util.kext.a[] aVarArr2 = com.quizlet.quizletandroid.util.kext.a.a;
                    return 1;
                }
                com.quizlet.quizletandroid.util.kext.a[] aVarArr3 = com.quizlet.quizletandroid.util.kext.a.a;
                return 2;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        DBUser dBUser;
        switch (this.c) {
            case 0:
                f holder = (f) f0;
                Intrinsics.checkNotNullParameter(holder, "holder");
                com.quizlet.quizletandroid.ui.group.classcontent.models.a aVar = (com.quizlet.quizletandroid.ui.group.classcontent.models.a) d(i);
                if (!(aVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.models.d)) {
                    if (!(aVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.models.c)) {
                        if (!(aVar instanceof com.quizlet.quizletandroid.ui.group.classcontent.models.e)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        d dVar = (d) holder;
                        com.quizlet.quizletandroid.ui.group.classcontent.models.e item = (com.quizlet.quizletandroid.ui.group.classcontent.models.e) aVar;
                        dVar.getClass();
                        Intrinsics.checkNotNullParameter(item, "item");
                        dVar.a.c(item.a);
                        return;
                    }
                    c cVar = (c) holder;
                    com.quizlet.quizletandroid.ui.group.classcontent.models.c item2 = (com.quizlet.quizletandroid.ui.group.classcontent.models.c) aVar;
                    cVar.getClass();
                    Intrinsics.checkNotNullParameter(item2, "item");
                    cVar.b = item2;
                    com.quizlet.quizletandroid.ui.group.classcontent.models.b bVar = item2.b;
                    if (bVar == null) {
                        cVar.a.g(item2.e, false);
                        return;
                    } else {
                        cVar.a.f(item2.e, bVar.b, bVar.e, bVar.c, bVar.d, false);
                        return;
                    }
                }
                e eVar = (e) holder;
                com.quizlet.quizletandroid.ui.group.classcontent.models.d item3 = (com.quizlet.quizletandroid.ui.group.classcontent.models.d) aVar;
                eVar.getClass();
                Intrinsics.checkNotNullParameter(item3, "item");
                eVar.b = item3;
                DBStudySet dBStudySet = new DBStudySet();
                dBStudySet.setId(item3.a);
                com.quizlet.quizletandroid.ui.group.classcontent.models.b bVar2 = item3.b;
                if (bVar2 != null) {
                    dBUser = new DBUser();
                    dBUser.setUsername(bVar2.b);
                    dBUser.setId(bVar2.a);
                    dBUser.setImageUrl(bVar2.c);
                    dBUser.setUserUpgradeType(bVar2.f);
                    dBUser.setIsVerified(bVar2.d);
                } else {
                    dBUser = null;
                }
                dBStudySet.setCreator(dBUser);
                dBStudySet.setNumTerms(item3.f);
                dBStudySet.setTitle(item3.e);
                dBStudySet.setPublishedTimestamp(Long.valueOf(item3.d));
                dBStudySet.setThumbnailUrl(item3.j);
                dBStudySet.setPasswordUse(item3.i);
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(Boolean.TRUE);
                Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                k.f(eVar.a, dBStudySet, false, bVarF, false);
                return;
            default:
                com.quizlet.quizletandroid.ui.preview.viewholder.b viewHolder = (com.quizlet.quizletandroid.ui.preview.viewholder.b) f0;
                Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
                Object objD = d(i);
                Intrinsics.checkNotNullExpressionValue(objD, "getItem(...)");
                viewHolder.c((com.quizlet.quizletandroid.ui.preview.dataclass.a) objD);
                return;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Object obj = this.d;
        switch (this.c) {
            case 0:
                Intrinsics.checkNotNullParameter(parent, "parent");
                com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a) obj;
                if (i == 0) {
                    LayoutInflater layoutInflaterFrom = LayoutInflater.from(parent.getContext());
                    int i2 = e.c;
                    View viewInflate = layoutInflaterFrom.inflate(R.layout.nav2_listitem_set, parent, false);
                    Intrinsics.d(viewInflate);
                    return new e(viewInflate, aVar);
                }
                if (i == 1) {
                    LayoutInflater layoutInflaterFrom2 = LayoutInflater.from(parent.getContext());
                    int i3 = c.c;
                    View viewInflate2 = layoutInflaterFrom2.inflate(R.layout.nav2_listitem_folder, parent, false);
                    Intrinsics.d(viewInflate2);
                    return new c(viewInflate2, aVar);
                }
                if (i != 2) {
                    throw new IllegalStateException(android.support.v4.media.session.a.f(i, "Unknown view type given: "));
                }
                LayoutInflater layoutInflaterFrom3 = LayoutInflater.from(parent.getContext());
                int i4 = d.b;
                View viewInflate3 = layoutInflaterFrom3.inflate(R.layout.listitem_section_header, parent, false);
                Intrinsics.d(viewInflate3);
                return new d(viewInflate3);
            default:
                Intrinsics.checkNotNullParameter(parent, "parent");
                LayoutInflater layoutInflaterFrom4 = LayoutInflater.from(parent.getContext());
                int i5 = com.quizlet.quizletandroid.ui.preview.viewholder.b.e;
                View viewInflate4 = layoutInflaterFrom4.inflate(R.layout.search_set_preview_view_holder, parent, false);
                Intrinsics.d(viewInflate4);
                Intrinsics.checkNotNullParameter(viewInflate4, "<this>");
                Intrinsics.checkNotNullParameter(parent, "parent");
                float fraction = viewInflate4.getResources().getFraction(R.fraction.study_preview_width_percent, 1, 1);
                viewInflate4.getLayoutParams().width = (int) (parent.getMeasuredWidth() * fraction);
                ViewGroup.LayoutParams layoutParams = viewInflate4.getLayoutParams();
                Intrinsics.e(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
                float f = (1 - fraction) / 2;
                com.quizlet.quizletandroid.util.kext.a[] aVarArr = com.quizlet.quizletandroid.util.kext.a.a;
                if (i == 0) {
                    marginLayoutParams.setMarginStart((int) (parent.getMeasuredWidth() * f));
                } else if (i == 1) {
                    marginLayoutParams.setMarginEnd((int) (parent.getMeasuredWidth() * f));
                }
                return new com.quizlet.quizletandroid.ui.preview.viewholder.b(viewInflate4, (com.quizlet.qutils.image.loading.a) obj);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.qutils.image.loading.a imageLoader) {
        super(com.quizlet.quizletandroid.ui.preview.adapter.a.d);
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.d = imageLoader;
    }
}
