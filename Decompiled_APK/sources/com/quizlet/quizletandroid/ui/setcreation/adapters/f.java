package com.quizlet.quizletandroid.ui.setcreation.adapters;

import android.net.Uri;
import android.os.Build;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Toast;
import androidx.appcompat.app.K;
import androidx.collection.C0219q;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.api.model.TermContentSuggestions;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.wrappers.RawJsonObject;
import com.quizlet.generated.enums.O1;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.widgets.QRichFormField;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.managers.CardFocusPosition;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.g;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.l;
import com.quizlet.quizletandroid.ui.setcreation.viewholders.m;
import com.quizlet.richtext.ui.toolbar.QRichTextToolbar;
import com.quizlet.uicommon.ui.common.views.QuizletPlusBadge;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.observers.h;
import io.reactivex.rxjava3.internal.operators.observable.W;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends AbstractC1361d0 {
    public final h A;
    public final com.google.android.material.textfield.a a;
    public final i b;
    public final com.google.android.gms.internal.appset.e c;
    public final com.quizlet.qutils.image.loading.a d;
    public final io.reactivex.rxjava3.subjects.d e;
    public boolean f;
    public androidx.core.util.c g;
    public final io.reactivex.rxjava3.subjects.d k;
    public String l;
    public String m;
    public String n;
    public String o;
    public ArrayList p;
    public final WeakReference r;
    public final androidx.work.impl.model.c s;
    public final K u;
    public final com.quizlet.quizletandroid.ui.setcreation.tracking.c w;
    public final com.quizlet.quizletandroid.ui.login.h x;
    public final QRichTextToolbar y;
    public final com.quizlet.richtext.rendering.c z;
    public int j = -1;
    public Boolean q = Boolean.TRUE;
    public boolean t = true;
    public boolean v = true;
    public final C0219q h = new C0219q((Object) null);
    public final C0219q i = new C0219q((Object) null);

    public f(EditSetFragment editSetFragment, o oVar, com.quizlet.qutils.image.loading.a aVar, i iVar, com.google.android.gms.internal.appset.e eVar, com.quizlet.quizletandroid.ui.login.h hVar, K k, com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar, QRichTextToolbar qRichTextToolbar, com.quizlet.richtext.rendering.c cVar2, androidx.work.impl.model.c cVar3, com.google.android.material.textfield.a aVar2) {
        this.r = new WeakReference(editSetFragment);
        this.s = cVar3;
        this.y = qRichTextToolbar;
        this.z = cVar2;
        this.d = aVar;
        io.reactivex.rxjava3.subjects.d dVar = new io.reactivex.rxjava3.subjects.d(new CardFocusPosition(-1, -1, null));
        this.k = dVar;
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        o oVar2 = io.reactivex.rxjava3.schedulers.e.b;
        W wS = dVar.h(10L, timeUnit, oVar2).s(oVar);
        final int i = 0;
        io.reactivex.rxjava3.functions.d dVar2 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.adapters.d
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i2;
                O1 o1;
                com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
                switch (i) {
                    case 0:
                        CardFocusPosition cardFocusPosition = (CardFocusPosition) obj;
                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) this.b.r.get();
                        if (aVar3 != null && (i2 = cardFocusPosition.a) >= 0 && (o1 = cardFocusPosition.c) != null) {
                            O1 o12 = O1.WORD;
                            if (o1 != o12) {
                                O1 o13 = O1.DEFINITION;
                                if (o1 == o13) {
                                    ((EditSetFragment) aVar3).W(i2 + 1, o13);
                                    break;
                                }
                            } else {
                                ((EditSetFragment) aVar3).W(i2 + 1, o12);
                                break;
                            }
                        }
                        break;
                    default:
                        androidx.core.util.c cVar4 = (androidx.core.util.c) obj;
                        f fVar = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar4 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
                        if (cVar4 != null && aVar4 != null) {
                            String title = (String) cVar4.a;
                            String description = (String) cVar4.b;
                            fVar.m();
                            if (((fVar.k() != null) & (true ^ org.apache.commons.lang3.e.c(title))) && !title.equals(fVar.n)) {
                                fVar.k().e("title");
                            }
                            fVar.n = title;
                            if (fVar.k() != null && !org.apache.commons.lang3.e.c(description) && !description.equals(fVar.o)) {
                                fVar.k().e(OTUXParamsKeys.OT_UX_DESCRIPTION);
                            }
                            fVar.o = description;
                            Intrinsics.checkNotNullParameter(title, "title");
                            Intrinsics.checkNotNullParameter(description, "description");
                            WeakReference weakReference = ((EditSetFragment) aVar4).x;
                            if (weakReference != null && (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
                                com.quizlet.quizletandroid.ui.setcreation.managers.i iVar2 = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y;
                                iVar2.o.i(new com.quizlet.infra.legacysyncengine.net.request.e(iVar2, title, description, 1), io.reactivex.rxjava3.internal.functions.d.e);
                                iVar2.e.a = false;
                                break;
                            }
                        }
                        break;
                }
            }
        };
        com.quizlet.billing.subscriptions.c cVar4 = new com.quizlet.billing.subscriptions.c(5);
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        this.A = (h) wS.u(dVar2, cVar4, bVar);
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        this.e = dVarZ;
        W wS2 = dVarZ.h(100L, timeUnit, oVar2).s(oVar);
        final int i2 = 1;
        wS2.u(new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.adapters.d
            public final /* synthetic */ f b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                int i22;
                O1 o1;
                com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar2;
                switch (i2) {
                    case 0:
                        CardFocusPosition cardFocusPosition = (CardFocusPosition) obj;
                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) this.b.r.get();
                        if (aVar3 != null && (i22 = cardFocusPosition.a) >= 0 && (o1 = cardFocusPosition.c) != null) {
                            O1 o12 = O1.WORD;
                            if (o1 != o12) {
                                O1 o13 = O1.DEFINITION;
                                if (o1 == o13) {
                                    ((EditSetFragment) aVar3).W(i22 + 1, o13);
                                    break;
                                }
                            } else {
                                ((EditSetFragment) aVar3).W(i22 + 1, o12);
                                break;
                            }
                        }
                        break;
                    default:
                        androidx.core.util.c cVar42 = (androidx.core.util.c) obj;
                        f fVar = this.b;
                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar4 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
                        if (cVar42 != null && aVar4 != null) {
                            String title = (String) cVar42.a;
                            String description = (String) cVar42.b;
                            fVar.m();
                            if (((fVar.k() != null) & (true ^ org.apache.commons.lang3.e.c(title))) && !title.equals(fVar.n)) {
                                fVar.k().e("title");
                            }
                            fVar.n = title;
                            if (fVar.k() != null && !org.apache.commons.lang3.e.c(description) && !description.equals(fVar.o)) {
                                fVar.k().e(OTUXParamsKeys.OT_UX_DESCRIPTION);
                            }
                            fVar.o = description;
                            Intrinsics.checkNotNullParameter(title, "title");
                            Intrinsics.checkNotNullParameter(description, "description");
                            WeakReference weakReference = ((EditSetFragment) aVar4).x;
                            if (weakReference != null && (bVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
                                com.quizlet.quizletandroid.ui.setcreation.managers.i iVar2 = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar2).y;
                                iVar2.o.i(new com.quizlet.infra.legacysyncengine.net.request.e(iVar2, title, description, 1), io.reactivex.rxjava3.internal.functions.d.e);
                                iVar2.e.a = false;
                                break;
                            }
                        }
                        break;
                }
            }
        }, io.reactivex.rxjava3.internal.functions.d.e, bVar);
        this.b = iVar;
        this.c = eVar;
        this.x = hVar;
        this.w = cVar;
        this.u = k;
        this.a = aVar2;
    }

    public static void l(boolean z, TermContentSuggestions termContentSuggestions) {
        String str = z ? "word\t" : "definition\t";
        TermContentSuggestions.Parameters parameters = termContentSuggestions.parameters;
        if (parameters == null) {
            timber.log.c.a.g("Received %s results, but the parameters are null", str);
            return;
        }
        List<TermContentSuggestions.Suggestions> list = termContentSuggestions.suggestions;
        if (list == null) {
            timber.log.c.a.g("Received %s results, but the suggestions are null for request %s, local term ID %s, lang codes '%s'/'%s' w/ prefix '%s' and word '%s'", str, termContentSuggestions.requestId, parameters.localTermId, parameters.wordLangCode, parameters.defLangCode, parameters.prefix, parameters.word);
        } else {
            timber.log.c.a.g("Received %d %s results, request id %s, local term ID %s, lang codes '%s'/'%s' w/ prefix '%s' and word '%s'", Integer.valueOf(list.size()), str, termContentSuggestions.requestId, parameters.localTermId, parameters.wordLangCode, parameters.defLangCode, parameters.prefix, parameters.word);
        }
    }

    public final void d(int i) {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) this.r.get();
        if (aVar == null) {
            return;
        }
        if (this.p.size() >= 2000) {
            Toast.makeText(((EditSetFragment) aVar).getContext(), R.string.max_terms_warning_toast, 0).show();
            return;
        }
        WeakReference weakReference = ((EditSetFragment) aVar).x;
        Intrinsics.d(weakReference);
        Object obj = weakReference.get();
        Intrinsics.d(obj);
        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) ((com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) obj)).y;
        iVar.getClass();
        DBTerm dBTerm = new DBTerm();
        dBTerm.setSetId(iVar.k.longValue());
        iVar.d.c(dBTerm);
        iVar.e.a = false;
        Intrinsics.checkNotNullExpressionValue(dBTerm, "createNewTerm(...)");
        f(i, dBTerm);
    }

    public final void f(int i, DBTerm dBTerm) {
        ArrayList arrayList;
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) this.r.get();
        if (aVar == null || (arrayList = this.p) == null) {
            return;
        }
        int iMin = Math.min(i, arrayList.size());
        this.p.add(iMin, dBTerm);
        int i2 = iMin + 1;
        notifyItemInserted(i2);
        ArrayList terms = this.p;
        EditSetFragment editSetFragment = (EditSetFragment) aVar;
        Intrinsics.checkNotNullParameter(terms, "terms");
        WeakReference weakReference = editSetFragment.x;
        if (weakReference != null && (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
            ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y.g(iMin, terms);
            editSetFragment.h0();
        }
        O1 o1 = O1.WORD;
        editSetFragment.W(i2, o1);
        this.k.b(new CardFocusPosition(iMin, i2, o1));
    }

    public final void g(int i, O1 o1) {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) this.r.get();
        if (aVar != null) {
            ((EditSetFragment) aVar).W(i, o1);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        ArrayList arrayList = this.p;
        if (arrayList == null) {
            return 1;
        }
        return arrayList.size() + 2;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        int itemViewType = getItemViewType(i);
        if (itemViewType != 2) {
            return itemViewType;
        }
        DBTerm dBTermJ = j(i);
        if (dBTermJ != null) {
            return dBTermJ.getLocalId();
        }
        return -1L;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        ArrayList arrayList = this.p;
        if (arrayList == null) {
            return 4;
        }
        if (i == 0) {
            return 1;
        }
        return i == arrayList.size() + 1 ? 3 : 2;
    }

    public final int h(long j) {
        if (this.p == null) {
            timber.log.c.b(new IllegalStateException("Attempting to find a term index by ID when no terms have been set yet"));
            return -1;
        }
        for (int i = 0; i < this.p.size(); i++) {
            if (((DBTerm) this.p.get(i)).getLocalId() == j || ((DBTerm) this.p.get(i)).getId() == j) {
                return i;
            }
        }
        return -1;
    }

    public final List i(O1 o1) {
        if (this.p == null) {
            return Collections.EMPTY_LIST;
        }
        ArrayList arrayList = new ArrayList();
        Iterator it2 = this.p.iterator();
        while (it2.hasNext()) {
            DBTerm dBTerm = (DBTerm) it2.next();
            if (o1 == O1.DEFINITION) {
                arrayList.add(dBTerm.getDefinition());
            } else {
                arrayList.add(dBTerm.getWord());
            }
        }
        return arrayList;
    }

    public final DBTerm j(int i) {
        int i2;
        ArrayList arrayList = this.p;
        if (arrayList != null && i - 1 >= 0 && i2 < arrayList.size()) {
            return (DBTerm) this.p.get(i2);
        }
        return null;
    }

    public final com.quizlet.quizletandroid.sessionhelpers.a k() {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) this.r.get();
        if (aVar != null) {
            EditSetFragment editSetFragment = (EditSetFragment) aVar;
            WeakReference weakReference = editSetFragment.x;
            com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar = weakReference != null ? (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get() : null;
            if ((bVar != null ? ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).m : null) != null) {
                WeakReference weakReference2 = editSetFragment.x;
                com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar2 = weakReference2 != null ? (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference2.get() : null;
                if (bVar2 != null) {
                    return ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar2).m;
                }
            }
        }
        return null;
    }

    public final void m() {
        androidx.core.util.c cVar = this.g;
        if (cVar == null) {
            return;
        }
        int iIntValue = ((Integer) cVar.a).intValue();
        this.g = null;
        notifyItemChanged(iIntValue, 100);
    }

    public final void n(O1 o1, String str) {
        if (o1 == O1.WORD) {
            this.l = str;
        } else if (o1 == O1.DEFINITION) {
            this.m = str;
        }
        notifyItemChanged(this.j, 800);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        onBindViewHolder(f0, i, new ArrayList());
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        if (i != 1) {
            if (i == 2) {
                LayoutInflater layoutInflaterFrom = LayoutInflater.from(viewGroup.getContext());
                float f = m.l;
                return new m(this, layoutInflaterFrom.inflate(R.layout.view_edit_set_term, viewGroup, false), this.d, this.b, this.u, this.s);
            }
            if (i == 3) {
                LayoutInflater layoutInflaterFrom2 = LayoutInflater.from(viewGroup.getContext());
                int i2 = com.quizlet.quizletandroid.ui.setcreation.viewholders.c.b;
                return new com.quizlet.quizletandroid.ui.setcreation.viewholders.c(this, layoutInflaterFrom2.inflate(R.layout.view_edit_set_new_card, viewGroup, false));
            }
            if (i != 4) {
                return null;
            }
            LayoutInflater layoutInflaterFrom3 = LayoutInflater.from(viewGroup.getContext());
            int i3 = com.quizlet.quizletandroid.ui.setcreation.viewholders.b.a;
            return new com.quizlet.quizletandroid.ui.setcreation.viewholders.b(layoutInflaterFrom3.inflate(R.layout.view_edit_set_loading, viewGroup, false));
        }
        View viewC = Z.c(viewGroup, R.layout.view_edit_set_set_summary, viewGroup, false);
        int i4 = R.id.edit_set_add_desc_button;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.edit_set_add_desc_button, viewC);
        if (qTextView != null) {
            i4 = R.id.edit_set_description_field;
            QFormField qFormField = (QFormField) AbstractC3375o2.c(R.id.edit_set_description_field, viewC);
            if (qFormField != null) {
                i4 = R.id.edit_set_title_field;
                QFormField qFormField2 = (QFormField) AbstractC3375o2.c(R.id.edit_set_title_field, viewC);
                if (qFormField2 != null) {
                    i4 = R.id.scan_document_container;
                    View viewC2 = AbstractC3375o2.c(R.id.scan_document_container, viewC);
                    if (viewC2 != null) {
                        int i5 = R.id.edit_set_scan_document_button;
                        if (((QTextView) AbstractC3375o2.c(R.id.edit_set_scan_document_button, viewC2)) != null) {
                            i5 = R.id.edit_set_scan_document_container;
                            LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_scan_document_container, viewC2);
                            if (linearLayout != null) {
                                i5 = R.id.edit_set_scan_document_image;
                                if (((ImageView) AbstractC3375o2.c(R.id.edit_set_scan_document_image, viewC2)) != null) {
                                    i5 = R.id.edit_set_scan_document_tooltip_container;
                                    View viewC3 = AbstractC3375o2.c(R.id.edit_set_scan_document_tooltip_container, viewC2);
                                    if (viewC3 != null) {
                                        i5 = R.id.scanDocumentQPlusBadge;
                                        QuizletPlusBadge quizletPlusBadge = (QuizletPlusBadge) AbstractC3375o2.c(R.id.scanDocumentQPlusBadge, viewC2);
                                        if (quizletPlusBadge != null) {
                                            return new g(this, new com.quizlet.features.infra.legacyadapter.databinding.h((ConstraintLayout) viewC, qTextView, qFormField, qFormField2, new com.quizlet.features.infra.legacyadapter.databinding.f((FrameLayout) viewC2, linearLayout, viewC3, quizletPlusBadge, 7), 4), this.c, this.x, this.a);
                                        }
                                    }
                                }
                            }
                        }
                        throw new NullPointerException("Missing required view with ID: ".concat(viewC2.getResources().getResourceName(i5)));
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(i4)));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i, List list) {
        boolean z;
        boolean z2 = f0 instanceof m;
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        if (!z2) {
            if (!(f0 instanceof g)) {
                if (!(f0 instanceof com.quizlet.quizletandroid.ui.setcreation.viewholders.c)) {
                    boolean z3 = f0 instanceof com.quizlet.quizletandroid.ui.setcreation.viewholders.b;
                    return;
                }
                com.quizlet.quizletandroid.ui.setcreation.viewholders.c cVar = (com.quizlet.quizletandroid.ui.setcreation.viewholders.c) f0;
                if (list.isEmpty() || list.contains(1000) || list.contains(Integer.valueOf(com.pubmatic.sdk.video.a.UNDEFINED_ERROR))) {
                    cVar.itemView.setVisibility(this.f ? 0 : 4);
                    return;
                }
                return;
            }
            g gVar2 = (g) f0;
            String str = this.n;
            String str2 = this.o;
            boolean zBooleanValue = this.q.booleanValue();
            if (!Intrinsics.b(gVar2.f, str)) {
                gVar2.f = str == null ? "" : str;
                gVar2.e().setText(str);
            }
            if (!Intrinsics.b(gVar2.g, str2)) {
                gVar2.g = str2 != null ? str2 : "";
                gVar2.c().setText(str2);
            }
            gVar2.g();
            if (zBooleanValue) {
                com.google.android.gms.internal.appset.e eVar = gVar2.c;
                com.google.android.gms.dynamite.d.e(((androidx.work.impl.model.c) eVar.c).u()).i(new com.quizlet.quizletandroid.ui.setcreation.viewholders.f(gVar2, 1), gVar);
                com.google.mlkit.common.internal.model.a aVar = (com.google.mlkit.common.internal.model.a) eVar.d;
                androidx.work.impl.model.c cVar2 = (androidx.work.impl.model.c) eVar.c;
                aVar.p(cVar2).i(new com.quizlet.quizletandroid.ui.setcreation.viewholders.f(gVar2, 2), new com.quizlet.billing.manager.d(timber.log.c.a, 12));
                io.reactivex.rxjava3.internal.operators.single.g gVarE = com.google.android.gms.dynamite.d.e(cVar2.u());
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(Boolean.valueOf(!((com.quizlet.scandocument.ui.d) eVar.b).a.getBoolean("PREF_SEEN_SCAN_DOCUMENT_TOOLTIP", false)));
                Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                com.google.android.gms.dynamite.d.b(gVarE, bVarF).i(new com.quizlet.quizletandroid.ui.setcreation.viewholders.f(gVar2, 0), gVar);
            } else {
                gVar2.d().setVisibility(8);
            }
            if (this.t) {
                gVar2.e().getEditText().post(new q(gVar2, 19));
                this.t = false;
                return;
            }
            return;
        }
        m mVar = (m) f0;
        DBTerm dBTermJ = j(i);
        if (dBTermJ == null) {
            return;
        }
        String str3 = this.l;
        String str4 = this.m;
        l lVar = mVar.b;
        String str5 = lVar.g;
        if (str5 == null || !str5.equals(str3)) {
            lVar.g = str3;
            QRichFormField qRichFormField = lVar.f;
            if (qRichFormField != null) {
                qRichFormField.setFormfieldAction(new com.quizlet.data.repository.qclass.c(27, lVar, lVar.k));
            }
        }
        l lVar2 = mVar.c;
        String str6 = lVar2.g;
        if (str6 == null || !str6.equals(str4)) {
            lVar2.g = str4;
            QRichFormField qRichFormField2 = lVar2.f;
            if (qRichFormField2 != null) {
                qRichFormField2.setFormfieldAction(new com.quizlet.data.repository.qclass.c(27, lVar2, lVar2.k));
            }
        }
        if (list.isEmpty()) {
            QRichTextToolbar mToolbar = this.y;
            Intrinsics.checkNotNullParameter(mToolbar, "mToolbar");
            com.quizlet.richtext.rendering.c richTextRenderer = this.z;
            Intrinsics.checkNotNullParameter(richTextRenderer, "richTextRenderer");
            mVar.f().setToolbar(mToolbar);
            mVar.f().setRichTextRenderer(richTextRenderer);
            mVar.h().setToolbar(mToolbar);
            mVar.h().setRichTextRenderer(richTextRenderer);
            mVar.g().setX(m.l);
            String word = dBTermJ.getWord();
            RawJsonObject wordRichText = dBTermJ.getWordRichText();
            String definition = dBTermJ.getDefinition();
            RawJsonObject definitionRichText = dBTermJ.getDefinitionRichText();
            z = true;
            if (Build.VERSION.SDK_INT >= 28) {
                ((io.reactivex.rxjava3.subjects.d) mVar.j.b).u(new com.quizlet.quizletandroid.ui.setcreation.viewholders.i(mVar, 1), gVar, io.reactivex.rxjava3.internal.functions.d.c);
            }
            mVar.b.a(word, null, wordRichText);
            lVar2.a(definition, null, definitionRichText);
            boolean z4 = this.v;
            mVar.b.c(null);
            mVar.c.c(null);
            mVar.g = z4;
        } else {
            z = true;
        }
        if (list.contains(100) || list.contains(200)) {
            androidx.core.util.c cVar3 = this.g;
            if (cVar3 == null) {
                mVar.c(DefinitionKt.NO_Float_VALUE, false, false);
            } else {
                mVar.c(((Float) this.g.b).floatValue(), ((Integer) cVar3.a).intValue() == i ? z : false, list.contains(200));
                this.g = new androidx.core.util.c((Integer) this.g.a, Float.valueOf(DefinitionKt.NO_Float_VALUE));
            }
        }
        if (list.contains(300)) {
            TermContentSuggestions termContentSuggestions = (TermContentSuggestions) this.h.c(dBTermJ.getLocalId());
            TermContentSuggestions termContentSuggestions2 = (TermContentSuggestions) this.i.c(dBTermJ.getLocalId());
            List<TermContentSuggestions.Suggestions> list2 = termContentSuggestions == null ? null : termContentSuggestions.suggestions;
            List<TermContentSuggestions.Suggestions> list3 = termContentSuggestions2 != null ? termContentSuggestions2.suggestions : null;
            boolean z5 = this.v;
            mVar.b.c(list2);
            mVar.c.c(list3);
            mVar.g = z5;
        }
        if (list.isEmpty() || list.contains(400)) {
            mVar.g().setActivated(this.j == i ? z : false);
        }
        if (list.isEmpty() || list.contains(Integer.valueOf(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR))) {
            String definitionImageUrl = dBTermJ.getDefinitionImageUrl();
            com.onetrust.otpublishers.headless.databinding.d dVar = mVar.a;
            if (definitionImageUrl != null) {
                ImageView editSetDefImage = (ImageView) dVar.d;
                Intrinsics.checkNotNullExpressionValue(editSetDefImage, "editSetDefImage");
                com.facebook.appevents.ml.f.j(0, 4, Uri.parse(definitionImageUrl), editSetDefImage, mVar.h);
            }
            FrameLayout editSetDefImageContainer = (FrameLayout) dVar.c;
            Intrinsics.checkNotNullExpressionValue(editSetDefImageContainer, "editSetDefImageContainer");
            editSetDefImageContainer.setVisibility(definitionImageUrl == null ? 8 : 0);
        }
        if (list.contains(Integer.valueOf(com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR))) {
            Intrinsics.checkNotNullParameter(O1.WORD, "portion");
            mVar.h().requestFocus();
        } else if (list.contains(700)) {
            O1 portion = O1.DEFINITION;
            Intrinsics.checkNotNullParameter(portion, "portion");
            if (portion == O1.WORD) {
                mVar.h().requestFocus();
            } else {
                mVar.f().requestFocus();
            }
        }
    }
}
