from core.auth.dependencies import getUserFromAccessToken
from strawberry.fastapi import GraphQLRouter
from strawberry.scalars import JSON
from strawberry.types import Info
from fastapi import Depends
import strawberry

async def getUserDetails(account = Depends(getUserFromAccessToken)):
  return { "user": account }


@strawberry.type
class Query:
  @strawberry.field
  def id(self, info: Info) -> str:
    return info.context['user'].get("_id")
  
  @strawberry.field
  def username(self, info: Info) -> str:
    return info.context['user'].get("username")
  
  @strawberry.field
  def email(self, info: Info) -> str:
    return info.context['user'].get("email")
  
  @strawberry.field
  def linkedServices(self, info: Info) -> JSON:
    return [{ 
      "name": service['name'],
      "username": service['username'],
    } for service in info.context['user'].get("services")]


schema = strawberry.Schema(Query)
graphql_app = GraphQLRouter(schema, context_getter=getUserDetails)