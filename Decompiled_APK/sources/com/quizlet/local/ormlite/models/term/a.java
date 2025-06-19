package com.quizlet.local.ormlite.models.term;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.quizlet.data.model.i2;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.wrappers.RawJsonObject;
import com.quizlet.local.ormlite.util.c;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h, c {
    public static final a a = new a();

    public static DBTerm a(i2 data) {
        Intrinsics.checkNotNullParameter(data, "data");
        DBTerm dBTerm = new DBTerm();
        dBTerm.setId(data.a);
        dBTerm.setLocalId(data.b);
        dBTerm.setSetId(data.c);
        dBTerm.setWord(data.e);
        dBTerm.setDefinition(data.f);
        dBTerm.setImageUrl(data.g);
        String str = data.h;
        dBTerm.setWordRichText(str != null ? new RawJsonObject(str) : null);
        String str2 = data.i;
        dBTerm.setDefinitionRichText(str2 != null ? new RawJsonObject(str2) : null);
        dBTerm.setWordAudioUrl(data.j);
        dBTerm.setDefinitionAudioUrl(data.k);
        dBTerm.setRank(data.d);
        return dBTerm;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List<DBTerm> localTerm = (List) obj;
        Intrinsics.checkNotNullParameter(localTerm, "localTerm");
        int iA = U.a(C.q(localTerm, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (DBTerm dBTerm : localTerm) {
            linkedHashMap.put(Long.valueOf(dBTerm.getId()), Long.valueOf(dBTerm.getLocalId()));
        }
        return linkedHashMap;
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public Object h(Object obj) {
        DBTerm local = (DBTerm) obj;
        Intrinsics.checkNotNullParameter(local, "local");
        long id = local.getId();
        long localId = local.getLocalId();
        long setId = local.getSetId();
        String word = local.getWord();
        if (word == null) {
            word = "";
        }
        String str = word;
        String definition = local.getDefinition();
        String definitionImageUrl = local.getDefinitionImageUrl();
        RawJsonObject wordRichText = local.getWordRichText();
        String value = wordRichText != null ? wordRichText.getValue() : null;
        RawJsonObject definitionRichText = local.getDefinitionRichText();
        return new i2(id, localId, setId, local.getRank(), str, definition, definitionImageUrl, value, definitionRichText != null ? definitionRichText.getValue() : null, local.getWordAudioUrl(), local.getDefinitionAudioUrl());
    }
}
