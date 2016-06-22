(ns grape.rest.route-test
  (:require [clojure.test :refer :all]
            [grape.rest.parser :refer :all]
            [grape.rest.route :refer :all]
            [cheshire.core :refer :all]
            [bidi.bidi :refer :all]
            [grape.fixtures :refer :all]
            [slingshot.slingshot :refer [throw+ try+]])
  (:import (org.bson.types ObjectId)
           (org.joda.time DateTime)))

(deftest route-handlers
  (testing "get resource handler"
    (load-fixtures)
    (let [resource {:url        "myresource"
                    :operations #{:read}}
          routes ["/" (build-resources-routes {:resources-registry {:myresource resource}})]
          resource-match (match-route routes "/myresource")
          item-match (match-route routes "/myresource/1234")]
      (is (nil? (match-route routes "/unknown")))
      (is (not (nil? (:handler resource-match))))
      (is (= "1234" (get-in item-match [:route-params :_id])))))

  (testing "get resource handler with extra endpoints"
    (load-fixtures)
    (let [resource {:url             "myresource"
                    :operations      #{:read}
                    :extra-endpoints [[["extra/" :param] identity]
                                      ["other" identity]]}
          routes ["/" (build-resource-routes {} resource)]
          resource-match (match-route routes "/myresource")
          item-match (match-route routes "/myresource/1234")
          extra-match (match-route routes "/extra/toto")
          other-match (match-route routes "/other")]
      (is (nil? (match-route routes "/unknown")))
      (is (not (nil? (:handler resource-match))))
      (is (= "1234" (get-in item-match [:route-params :_id])))
      (is (= "toto" (get-in extra-match [:route-params :param])))
      (is (not (nil? (:handler other-match)))))))

(deftest get-resource
  (testing "get public users"
    (load-fixtures)
    (let [routes ["/" (build-resources-routes deps)]
          match (match-route routes "/public_users")
          handler (:handler match)
          request {:query-params {"query" ""} :request-method :get}
          resp (:body (handler request))]
      (is (= 3 (:_count resp)))
      (is (= #{:_id :username} (->> (:_items resp)
                                    first
                                    keys
                                    (into #{}))))
      (is (= #{"user 1" "user 2" "user 3"} (->> (:_items resp)
                                                (map :username)
                                                (into #{})))))))

(deftest create-resource
  (testing "create - validation fails - required fields"
    (let [routes ["/" (build-resources-routes deps)]
          match (match-route routes "/users")
          handler (:handler match)
          request {:query-params {"query" ""} :body {} :request-method :post}
          resp (handler request)]
      (is (= 422 (:status resp)))
      ))

  (testing "create - validation fails - company not found"
    (load-fixtures)
    (let [routes ["/" (build-resources-routes deps)]
          match (match-route routes "/users")
          handler (:handler match)
          request {:query-params {"query" ""} :body {:company  (ObjectId. "caccccccccccccccccccccc9")
                                                     :username "me"
                                                     :email    "coucou@coucou.com"
                                                     :password "secret"} :request-method :post}
          resp (handler request)]
      (is (= 422 (:status resp)))
      (is (= {:company "the resource should exist"} (:body resp)))
      ))

  (testing "create success"
    (load-fixtures)
    (let [routes ["/" (build-resources-routes deps)]
          match (match-route routes "/users")
          handler (:handler match)
          request {:query-params {"query" ""} :body {:company  (ObjectId. "caccccccccccccccccccccc1")
                                                     :username "me"
                                                     :email    "coucou@coucou.com"
                                                     :password "secret"} :request-method :post}
          resp (handler request)
          inserted-id (get-in resp [:body :_id])]
      (is (not (nil? inserted-id)))
      (let [match (match-route routes (str "/users/" inserted-id))
            handler (:handler match)
            request (merge {:auth           {:auth_id (str inserted-id)}
                            :request-method :get}
                           (select-keys match [:route-params]))
            resp (handler request)]
        (is (= "me" (get-in resp [:body :username])))
        (is (= inserted-id (get-in resp [:body :_id]))))
      (let [match (match-route routes (str "/me"))
            handler (:handler match)
            request {:auth           {:auth_id (str inserted-id)}
                     :request-method :get}
            resp (handler request)]
        (is (= "me" (get-in resp [:body :username])))
        (is (= inserted-id (get-in resp [:body :_id]))))))

  (testing "create a comment should inject auth field when not specified"
    (load-fixtures)
    (let [routes ["/" (build-resources-routes deps)]
          match (match-route routes "/comments")
          handler (:handler match)
          request {:body           {:text    "coucou !"
                                    :company "caccccccccccccccccccccc1"}
                   :auth           {:auth_id "aaaaaaaaaaaaaaaaaaaaaaa1"}
                   :request-method :post}
          resp (handler request)
          inserted-id (get-in resp [:body :_id])]
      (is (not (nil? inserted-id)))
      (let [match (match-route routes (str "/comments/" inserted-id))
            handler (:handler match)
            request (merge {:auth           {:auth_id (str inserted-id)}
                            :request-method :get}
                           (select-keys match [:route-params]))
            resp (handler request)]
        (is (= "coucou !" (get-in resp [:body :text])))
        (is (= inserted-id (get-in resp [:body :_id]))))))

  (testing "create a comment specifying itself as a user should pass"
    (load-fixtures)
    (let [routes ["/" (build-resources-routes deps)]
          match (match-route routes "/comments")
          handler (:handler match)
          request {:body           {:text    "coucou !"
                                    :company "caccccccccccccccccccccc1"
                                    :user    "aaaaaaaaaaaaaaaaaaaaaaa1"}
                   :auth           {:auth_id "aaaaaaaaaaaaaaaaaaaaaaa1"}
                   :request-method :post}
          resp (handler request)
          inserted-id (get-in resp [:body :_id])]
      (is (not (nil? inserted-id)))
      (let [match (match-route routes (str "/comments/" inserted-id))
            handler (:handler match)
            request (merge {:auth           {:auth_id (str inserted-id)}
                            :request-method :get}
                           (select-keys match [:route-params]))
            resp (handler request)]
        (is (= "coucou !" (get-in resp [:body :text])))
        (is (= inserted-id (get-in resp [:body :_id]))))))

  (testing "create a comment for another user should be forbidden"
    (load-fixtures)
    (let [routes ["/" (build-resources-routes deps)]
          match (match-route routes "/comments")
          handler (:handler match)
          request {:body           {:text    "coucou !"
                                    :company "caccccccccccccccccccccc1"
                                    :user    "aaaaaaaaaaaaaaaaaaaaaaa2"}
                   :auth           {:auth_id "aaaaaaaaaaaaaaaaaaaaaaa1"}
                   :request-method :post}
          resp (handler request)]
      (is (= 403 (:status resp)))))

  (testing "create a comment should insert _created and _updated automatically"
    (load-fixtures)
    (let [routes ["/" (build-resources-routes deps)]
          match (match-route routes "/comments")
          handler (:handler match)
          request {:body           {:text    "coucou !"
                                    :company "caccccccccccccccccccccc1"}
                   :auth           {:auth_id "aaaaaaaaaaaaaaaaaaaaaaa1"}
                   :request-method :post}
          resp (handler request)]
      (is (instance? DateTime (get-in resp [:body :_created]))))))