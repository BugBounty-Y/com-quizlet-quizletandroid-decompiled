package com.quizlet.explanations.myexplanations.ui.recyclerview;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.navigation.compose.o;
import androidx.recyclerview.widget.AbstractC1358c;
import androidx.recyclerview.widget.F0;
import com.quizlet.explanations.databinding.w;
import com.quizlet.explanations.textbook.chaptermenu.recyclerview.k;
import com.quizlet.quizletandroid.R;
import com.quizlet.upgrade.data.q;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends com.quizlet.baserecyclerview.b {
    public final /* synthetic */ int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(AbstractC1358c abstractC1358c, int i) {
        super(abstractC1358c);
        this.c = i;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public int getItemViewType(int i) {
        switch (this.c) {
            case 4:
                com.quizlet.explanations.textbook.chaptermenu.recyclerview.a aVar = (com.quizlet.explanations.textbook.chaptermenu.recyclerview.a) d(i);
                if (aVar instanceof com.quizlet.explanations.textbook.chaptermenu.recyclerview.i) {
                    return 0;
                }
                if (aVar instanceof com.quizlet.explanations.textbook.chaptermenu.recyclerview.d) {
                    return 1;
                }
                if (aVar instanceof com.quizlet.explanations.textbook.chaptermenu.recyclerview.c) {
                    return 2;
                }
                throw new NoWhenBranchMatchedException();
            case 5:
                com.quizlet.explanations.textbook.tableofcontents.recyclerview.a aVar2 = (com.quizlet.explanations.textbook.tableofcontents.recyclerview.a) d(i);
                if (aVar2 instanceof com.quizlet.explanations.textbook.tableofcontents.recyclerview.b) {
                    return 0;
                }
                if (aVar2 instanceof com.quizlet.explanations.textbook.tableofcontents.recyclerview.d) {
                    return 1;
                }
                throw new NoWhenBranchMatchedException();
            default:
                return super.getItemViewType(i);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        switch (this.c) {
            case 0:
                d holder = (d) f0;
                Intrinsics.checkNotNullParameter(holder, "holder");
                Object objD = d(i);
                Intrinsics.checkNotNullExpressionValue(objD, "getItem(...)");
                a item = (a) objD;
                holder.getClass();
                Intrinsics.checkNotNullParameter(item, "item");
                holder.d.setContent(new androidx.compose.runtime.internal.d(true, 85394138, new o(10, item.a, item.b)));
                break;
            case 1:
                e holder2 = (e) f0;
                Intrinsics.checkNotNullParameter(holder2, "holder");
                Object objD2 = d(i);
                Intrinsics.checkNotNullExpressionValue(objD2, "getItem(...)");
                com.quizlet.explanations.myexplanations.data.h item2 = (com.quizlet.explanations.myexplanations.data.h) objD2;
                holder2.getClass();
                Intrinsics.checkNotNullParameter(item2, "item");
                ((w) holder2.e()).b.setText(item2.b);
                break;
            case 2:
                g holder3 = (g) f0;
                Intrinsics.checkNotNullParameter(holder3, "holder");
                Object objD3 = d(i);
                Intrinsics.checkNotNullExpressionValue(objD3, "getItem(...)");
                f item3 = (f) objD3;
                holder3.getClass();
                Intrinsics.checkNotNullParameter(item3, "item");
                holder3.d.setContent(new androidx.compose.runtime.internal.d(true, 1621811134, new o(12, item3.a, item3.b)));
                break;
            case 3:
                i holder4 = (i) f0;
                Intrinsics.checkNotNullParameter(holder4, "holder");
                Object objD4 = d(i);
                Intrinsics.checkNotNullExpressionValue(objD4, "getItem(...)");
                h item4 = (h) objD4;
                holder4.getClass();
                Intrinsics.checkNotNullParameter(item4, "item");
                holder4.d.setContent(new androidx.compose.runtime.internal.d(true, 1617951838, new o(14, item4.a, item4.b)));
                break;
            case 4:
                com.quizlet.explanations.textbook.chaptermenu.recyclerview.b holder5 = (com.quizlet.explanations.textbook.chaptermenu.recyclerview.b) f0;
                Intrinsics.checkNotNullParameter(holder5, "holder");
                com.quizlet.explanations.textbook.chaptermenu.recyclerview.a aVar = (com.quizlet.explanations.textbook.chaptermenu.recyclerview.a) d(i);
                if (!(holder5 instanceof k)) {
                    if (!(holder5 instanceof com.quizlet.explanations.textbook.chaptermenu.recyclerview.f)) {
                        if (holder5 instanceof com.quizlet.explanations.textbook.chaptermenu.recyclerview.h) {
                            Intrinsics.e(aVar, "null cannot be cast to non-null type com.quizlet.explanations.textbook.chaptermenu.recyclerview.ChapterMenuExercise");
                            ((com.quizlet.explanations.textbook.chaptermenu.recyclerview.h) holder5).c((com.quizlet.explanations.textbook.chaptermenu.recyclerview.c) aVar);
                            break;
                        }
                    } else {
                        Intrinsics.e(aVar, "null cannot be cast to non-null type com.quizlet.explanations.textbook.chaptermenu.recyclerview.ChapterMenuExerciseGroup");
                        ((com.quizlet.explanations.textbook.chaptermenu.recyclerview.f) holder5).c((com.quizlet.explanations.textbook.chaptermenu.recyclerview.d) aVar);
                        break;
                    }
                } else {
                    Intrinsics.e(aVar, "null cannot be cast to non-null type com.quizlet.explanations.textbook.chaptermenu.recyclerview.ChapterMenuSection");
                    ((k) holder5).c((com.quizlet.explanations.textbook.chaptermenu.recyclerview.i) aVar);
                    break;
                }
                break;
            case 5:
                com.quizlet.baserecyclerview.c holder6 = (com.quizlet.baserecyclerview.c) f0;
                Intrinsics.checkNotNullParameter(holder6, "holder");
                com.quizlet.explanations.textbook.tableofcontents.recyclerview.a aVar2 = (com.quizlet.explanations.textbook.tableofcontents.recyclerview.a) d(i);
                if (!(holder6 instanceof com.quizlet.explanations.textbook.tableofcontents.recyclerview.c)) {
                    if (holder6 instanceof com.quizlet.explanations.textbook.tableofcontents.recyclerview.f) {
                        Intrinsics.e(aVar2, "null cannot be cast to non-null type com.quizlet.explanations.textbook.tableofcontents.recyclerview.ChapterItem");
                        ((com.quizlet.explanations.textbook.tableofcontents.recyclerview.f) holder6).c((com.quizlet.explanations.textbook.tableofcontents.recyclerview.d) aVar2);
                        break;
                    }
                } else {
                    com.quizlet.explanations.textbook.tableofcontents.recyclerview.c cVar = (com.quizlet.explanations.textbook.tableofcontents.recyclerview.c) holder6;
                    Intrinsics.e(aVar2, "null cannot be cast to non-null type com.quizlet.explanations.textbook.tableofcontents.recyclerview.ChapterHeader");
                    cVar.getClass();
                    Intrinsics.checkNotNullParameter((com.quizlet.explanations.textbook.tableofcontents.recyclerview.b) aVar2, "item");
                    ((com.quizlet.explanations.databinding.o) cVar.e()).b.setText(R.string.chapter_header_title);
                    break;
                }
                break;
            default:
                com.quizlet.upgrade.ui.featurelist.a holder7 = (com.quizlet.upgrade.ui.featurelist.a) f0;
                Intrinsics.checkNotNullParameter(holder7, "holder");
                q qVar = (q) d(i);
                Intrinsics.d(qVar);
                holder7.c(qVar);
                break;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        switch (this.c) {
            case 0:
                Intrinsics.checkNotNullParameter(parent, "parent");
                Context context = parent.getContext();
                Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                return new d(new ComposeView(context, null, 6));
            case 1:
                Intrinsics.checkNotNullParameter(parent, "parent");
                View itemView = LayoutInflater.from(parent.getContext()).inflate(R.layout.listitem_my_explanations_header, parent, false);
                Intrinsics.d(itemView);
                Intrinsics.checkNotNullParameter(itemView, "itemView");
                return new e(itemView);
            case 2:
                Intrinsics.checkNotNullParameter(parent, "parent");
                Context context2 = parent.getContext();
                Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
                return new g(new ComposeView(context2, null, 6));
            case 3:
                Intrinsics.checkNotNullParameter(parent, "parent");
                Context context3 = parent.getContext();
                Intrinsics.checkNotNullExpressionValue(context3, "getContext(...)");
                return new i(new ComposeView(context3, null, 6));
            case 4:
                Intrinsics.checkNotNullParameter(parent, "parent");
                if (i == 0) {
                    return new k(com.quizlet.baserecyclerview.b.g(parent, R.layout.listitem_chapter_menu_item));
                }
                if (i == 1) {
                    return new com.quizlet.explanations.textbook.chaptermenu.recyclerview.f(com.quizlet.baserecyclerview.b.g(parent, R.layout.listitem_chapter_menu_item));
                }
                if (i == 2) {
                    return new com.quizlet.explanations.textbook.chaptermenu.recyclerview.h(com.quizlet.baserecyclerview.b.g(parent, R.layout.listitem_chapter_menu_item));
                }
                throw new IllegalStateException(i + " is an invalid viewType");
            case 5:
                Intrinsics.checkNotNullParameter(parent, "parent");
                if (i == 0) {
                    View view = com.quizlet.baserecyclerview.b.g(parent, R.layout.listitem_chapter_header);
                    Intrinsics.checkNotNullParameter(view, "view");
                    return new com.quizlet.explanations.textbook.tableofcontents.recyclerview.c(view);
                }
                if (i == 1) {
                    return new com.quizlet.explanations.textbook.tableofcontents.recyclerview.f(com.quizlet.baserecyclerview.b.g(parent, R.layout.listitem_chapter_item));
                }
                throw new IllegalStateException(i + " is an invalid viewType");
            default:
                Intrinsics.checkNotNullParameter(parent, "parent");
                View view2 = com.quizlet.baserecyclerview.b.g(parent, R.layout.list_item_feature);
                Intrinsics.checkNotNullParameter(view2, "view");
                return new com.quizlet.upgrade.ui.featurelist.a(view2);
        }
    }
}
