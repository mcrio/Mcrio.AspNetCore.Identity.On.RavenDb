<img src="./ravendb-logo.png" height="100px" alt="ravendb" />
<img src="./asp-net-core-logo.png" height="100px" alt="asp net core" />

# ASP.NET Core Identity on RavenDB 
A RavenDb *copy of the original EntityFramework user and role stores implementation.
Use RavenDb to store your user and role entities. Covers most of the tests implemented 
by the official EntityFramework stores.

#### Why implementing another RavenDb store solution as there were at lest two more related projects at that point?
At the time when this solution was implemented the other projects were not flexible enough for 
my requirements in terms of ID generation and extensibility.
_(I am writing this document more than a year later so there probably have been other reasons I don't remember any more)._

### * Missing functionality compare to official EF Core store implementation

- Support for [[PersonalData]](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.personaldataattribute?view=aspnetcore-5.0) attribute in terms of DB level encryption of properties annotated with this attribute.

