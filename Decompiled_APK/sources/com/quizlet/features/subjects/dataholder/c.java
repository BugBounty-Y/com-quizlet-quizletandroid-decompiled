package com.quizlet.features.subjects.dataholder;

import com.quizlet.generated.enums.I1;
import com.quizlet.generated.enums.K1;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.V;

/* loaded from: classes3.dex */
public abstract class c {
    public static final Object a;

    static {
        I1 i1 = I1.ARTS_AND_HUMANITIES;
        com.quizlet.features.subjects.model.a aVar = new com.quizlet.features.subjects.model.a(K1.ART_HISTORY, B.j(559640027L, 217967555L));
        com.quizlet.features.subjects.model.a aVar2 = new com.quizlet.features.subjects.model.a(K1.DANCE, A.b(911754491L));
        K1 k1 = K1.ENGLISH;
        Pair pair = new Pair(i1, new com.quizlet.features.subjects.model.b(i1, B.j(aVar, aVar2, new com.quizlet.features.subjects.model.a(k1, B.j(792539386L, 151933276L, 572920350L, 733474379L, 217868788L, 183189650L, 13272416L, 845265211L, 416600357L, 554882355L, 414226939L, 267220822L, 784463404L, 147066786L, 469557911L)), new com.quizlet.features.subjects.model.a(K1.LINGUISTICS, B.j(151933276L, 733474379L, 217868788L, 416600357L, 414226939L)), new com.quizlet.features.subjects.model.a(K1.LITERATURE, B.j(572920350L, 13272416L, 845265211L, 147066786L, 469557911L)), new com.quizlet.features.subjects.model.a(K1.VOCABULARY, B.j(183189650L, 267220822L, 784463404L)), new com.quizlet.features.subjects.model.a(K1.HISTORY, B.j(45794539L, 27992550L, 516066890L)))));
        I1 i12 = I1.LANGUAGES;
        Pair pair2 = new Pair(i12, new com.quizlet.features.subjects.model.b(i12, B.j(new com.quizlet.features.subjects.model.a(k1, B.j(438331823L, 459935333L, 470998361L, 327418979L)), new com.quizlet.features.subjects.model.a(K1.OTHER_LANGUAGES, B.j(620566024L, 593726784L, 479340543L, 414232510L, 494150982L, 217969776L, 439656709L, 575044392L, 154229000L, 417980764L, 277499655L, 365902169L, 515867895L, 267999460L, 257067304L, 250088137L, 363997364L, 237950534L, 567395270L)), new com.quizlet.features.subjects.model.a(K1.SPANISH, B.j(310672123L, 343514507L, 270019636L)), new com.quizlet.features.subjects.model.a(K1.GERMAN, A.b(443927917L)), new com.quizlet.features.subjects.model.a(K1.LATIN, A.b(35113950L)))));
        I1 i13 = I1.MATH;
        Pair pair3 = new Pair(i13, new com.quizlet.features.subjects.model.b(i13, B.j(new com.quizlet.features.subjects.model.a(K1.MATH, A.b(341499739L)), new com.quizlet.features.subjects.model.a(K1.ALGEBRA, B.j(315742859L, 221389988L, 330193855L, 347341274L, 321839196L, 434457299L, 234679604L, 229190292L, 262561997L)), new com.quizlet.features.subjects.model.a(K1.ARITHMETIC, B.j(194803472L, 61824787L)), new com.quizlet.features.subjects.model.a(K1.DISCRETE_MATH, B.j(312844718L, 846406096L)), new com.quizlet.features.subjects.model.a(K1.GEOMETRY, A.b(287421499L)), new com.quizlet.features.subjects.model.a(K1.MATH_FOUNDATIONS, A.b(269136484L)), new com.quizlet.features.subjects.model.a(K1.PROBABILITY, A.b(468942502L)), new com.quizlet.features.subjects.model.a(K1.STATISTICS, A.b(148308628L)))));
        I1 i14 = I1.SCIENCE;
        Pair pair4 = new Pair(i14, new com.quizlet.features.subjects.model.b(i14, B.j(new com.quizlet.features.subjects.model.a(K1.CHEMISTRY, B.j(13491157L, 84758531L, 286748811L, 223949898L, 4410161L, 2855398L, 16891565L, 46806377L, 4179936L, 148940988L, 7345584L, 414196955L)), new com.quizlet.features.subjects.model.a(K1.EARTH_SCIENCE, B.j(509728927L, 300701123L, 29377051L, 17762948L, 312401304L, 208975901L)), new com.quizlet.features.subjects.model.a(K1.PHYSICS, B.j(440792222L, 146426248L)), new com.quizlet.features.subjects.model.a(K1.SPACE_SCIENCE, B.j(193312601L, 257812453L, 208975901L)))));
        I1 i15 = I1.SOCIAL_SCIENCE;
        a = V.f(pair, pair2, pair3, pair4, new Pair(i15, new com.quizlet.features.subjects.model.b(i15, B.j(new com.quizlet.features.subjects.model.a(K1.ANTHROPOLOGY, B.j(306756037L, 537679835L)), new com.quizlet.features.subjects.model.a(K1.BUSINESS, B.j(550893830L, 582157725L, 241995243L)), new com.quizlet.features.subjects.model.a(K1.LAW, B.j(681641310L, 6022897L, 90567731L, 462933888L, 588371270L, 306944632L, 556471664L, 814602345L, 837808173L, 231993996L, 151940099L, 475571171L, 79546890L))))));
    }
}
